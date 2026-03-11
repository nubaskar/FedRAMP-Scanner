// ---------------------------------------------------------------------------
// FedRAMP Cloud Compliance Scanner — Azure Bicep deployment template.
//
// Deploys FastAPI backend on Azure Container Apps with PostgreSQL Flexible
// Server, Blob Storage + CDN for frontend, Key Vault, and supporting infra.
//
// FIRST DEPLOYMENT:
//   Leave containerImage empty. A placeholder init container will be used.
//   After deployment succeeds, build & push your Docker image to ACR, then
//   redeploy with containerImage set to the full ACR image path.
//
// KEY VAULT NAME CONFLICT:
//   If redeploying after a failed attempt, purge the soft-deleted vault first:
//     az keyvault purge --name <vault-name>
//     az keyvault list-deleted --query "[].name" -o tsv
// ---------------------------------------------------------------------------

// ===========================================================================
// Parameters
// ===========================================================================

@allowed([
  'dev'
  'staging'
  'prod'
])
@description('Deployment environment')
param environment string = 'dev'

@description('Azure region for all resources')
param location string = 'eastus'


@description('PostgreSQL SKU name')
param postgresSkuName string = 'Standard_B1ms'

@description('PostgreSQL SKU tier')
@allowed([
  'Burstable'
  'GeneralPurpose'
  'MemoryOptimized'
])
param postgresSkuTier string = 'Burstable'

@description('PostgreSQL storage size in GB')
param postgresStorageGB int = 32

@description('Minimum number of container replicas')
param minReplicas int = 1

@description('Maximum number of container replicas')
param maxReplicas int = 3

@description('Container image (full ACR path with tag). Leave empty for first deployment — a placeholder init container will be used. After deployment, push your image to ACR and update the container app.')
param containerImage string = ''

// ===========================================================================
// Variables
// ===========================================================================

var prefix = 'fedramp-scanner'
var uniqueSuffix = uniqueString(resourceGroup().id, prefix)
var resourcePrefix = '${prefix}-${environment}'
var isProduction = environment == 'prod'
var useCustomImage = containerImage != ''
// For first deployment, use a public init image. After deployment, push your
// Docker image to ACR and redeploy with the containerImage parameter.
var initImage = 'mcr.microsoft.com/k8se/quickstart:latest'
var resolvedImage = useCustomImage ? containerImage : initImage

var tags = {
  Project: 'FedRAMP-Scanner'
  Environment: environment
  ManagedBy: 'Bicep'
}

// ===========================================================================
// Virtual Network
// ===========================================================================

resource vnet 'Microsoft.Network/virtualNetworks@2024-01-01' = {
  name: '${resourcePrefix}-vnet'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'container-apps'
        properties: {
          addressPrefix: '10.0.0.0/23'
          delegations: [
            {
              name: 'Microsoft.App.environments'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        name: 'postgresql'
        properties: {
          addressPrefix: '10.0.2.0/24'
          delegations: [
            {
              name: 'Microsoft.DBforPostgreSQL.flexibleServers'
              properties: {
                serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers'
              }
            }
          ]
        }
      }
      {
        name: 'private-endpoints'
        properties: {
          addressPrefix: '10.0.3.0/24'
        }
      }
    ]
  }
}

// ===========================================================================
// Private DNS Zone for PostgreSQL
// ===========================================================================

resource privateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: '${resourcePrefix}.private.postgres.database.azure.com'
  location: 'global'
  tags: tags
}

resource privateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: privateDnsZone
  name: '${resourcePrefix}-pg-dns-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

// ===========================================================================
// Log Analytics Workspace
// ===========================================================================

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${resourcePrefix}-logs'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: isProduction ? 90 : 30
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

// ===========================================================================
// Key Vault
// ===========================================================================

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: take('kv-${environment}-${uniqueString(resourceGroup().id, 'keyvault')}', 24)
  location: location
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: isProduction ? 90 : 7
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

// --- Key Vault Secrets ---

resource secretDbPassword 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'database-password'
  properties: {
    value: dbAdminPassword
  }
}

resource secretJwt 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'jwt-secret'
  properties: {
    value: jwtSecret
  }
}

resource secretEncryptionKey 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'encryption-key'
  properties: {
    value: encryptionKey
  }
}

resource secretDbConnectionString 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'database-connection-string'
  properties: {
    value: 'postgresql://fedramp_admin:${dbAdminPassword}@${postgresServer.properties.fullyQualifiedDomainName}:5432/fedramp_scanner?sslmode=require'
  }
}

// Secure parameters (not stored in template)
@secure()
@description('PostgreSQL administrator password')
param dbAdminPassword string

@secure()
@description('JWT signing secret')
param jwtSecret string

@secure()
@description('Client credential encryption key')
param encryptionKey string

@description('Microsoft Entra ID tenant ID for SSO')
param azureAdTenantId string = ''

@description('Microsoft Entra ID application (client) ID for SSO')
param azureAdClientId string = ''

@secure()
@description('Microsoft Entra ID client secret for SSO')
param azureAdClientSecret string = ''

@description('Frontend URL for SSO redirect (e.g. https://your-frontend-url)')
param frontendUrl string = ''

// ===========================================================================
// Azure Database for PostgreSQL Flexible Server
// ===========================================================================

resource postgresServer 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: '${resourcePrefix}-pg-${uniqueSuffix}'
  location: location
  tags: tags
  sku: {
    name: postgresSkuName
    tier: postgresSkuTier
  }
  properties: {
    version: '16'
    administratorLogin: 'fedramp_admin'
    administratorLoginPassword: dbAdminPassword
    storage: {
      storageSizeGB: postgresStorageGB
    }
    backup: {
      backupRetentionDays: isProduction ? 14 : 7
      geoRedundantBackup: isProduction ? 'Enabled' : 'Disabled'
    }
    highAvailability: {
      mode: (isProduction && postgresSkuTier != 'Burstable') ? 'ZoneRedundant' : 'Disabled'
    }
    network: {
      delegatedSubnetResourceId: vnet.properties.subnets[1].id
      privateDnsZoneArmResourceId: privateDnsZone.id
    }
  }
  dependsOn: [
    privateDnsZoneLink
  ]
}

resource postgresDatabase 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = {
  parent: postgresServer
  name: 'fedramp_scanner'
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
}

// SSL enforcement configuration
resource postgresSslConfig 'Microsoft.DBforPostgreSQL/flexibleServers/configurations@2024-08-01' = {
  parent: postgresServer
  name: 'require_secure_transport'
  properties: {
    value: 'on'
    source: 'user-override'
  }
}

// ===========================================================================
// Azure Container Registry
// ===========================================================================

resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' = {
  name: replace('${prefix}${environment}${uniqueSuffix}', '-', '')
  location: location
  tags: tags
  sku: {
    name: isProduction ? 'Standard' : 'Basic'
  }
  properties: {
    adminUserEnabled: true
    publicNetworkAccess: 'Enabled'
  }
}

// ===========================================================================
// Container App Environment
// ===========================================================================

resource containerAppEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${resourcePrefix}-env'
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
    vnetConfiguration: {
      infrastructureSubnetId: vnet.properties.subnets[0].id
      internal: false
    }
    zoneRedundant: isProduction
  }
}

// ===========================================================================
// Container App (FastAPI Backend)
// ===========================================================================

resource containerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${resourcePrefix}-api'
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: useCustomImage ? 8000 : 80
        transport: 'auto'
        corsPolicy: {
          allowedOrigins: !empty(frontendUrl) ? [
            frontendUrl
          ] : [
            '*'
          ]
          allowedMethods: [
            'GET'
            'POST'
            'PUT'
            'DELETE'
            'OPTIONS'
          ]
          allowedHeaders: [
            '*'
          ]
        }
        traffic: [
          {
            latestRevision: true
            weight: 100
          }
        ]
      }
      registries: useCustomImage ? [
        {
          server: acr.properties.loginServer
          username: acr.listCredentials().username
          passwordSecretRef: 'acr-password'
        }
      ] : []
      secrets: concat(
        useCustomImage ? [
          {
            name: 'acr-password'
            value: acr.listCredentials().passwords[0].value
          }
        ] : [],
        [
          {
            name: 'database-url'
            value: 'postgresql://fedramp_admin:${dbAdminPassword}@${postgresServer.properties.fullyQualifiedDomainName}:5432/fedramp_scanner?sslmode=require'
          }
          {
            name: 'secret-key'
            value: jwtSecret
          }
          {
            name: 'encryption-key'
            value: encryptionKey
          }
        ],
        !empty(azureAdClientSecret) ? [
          {
            name: 'azure-ad-client-secret'
            value: azureAdClientSecret
          }
        ] : []
      )
    }
    template: {
      containers: [
        {
          name: 'fedramp-scanner-api'
          image: resolvedImage
          resources: {
            cpu: json('1.0')
            memory: '2.0Gi'
          }
          env: concat([
            {
              name: 'ENVIRONMENT'
              value: environment
            }
            {
              name: 'DATABASE_URL'
              secretRef: 'database-url'
            }
            {
              name: 'SECRET_KEY'
              secretRef: 'secret-key'
            }
            {
              name: 'ENCRYPTION_KEY'
              secretRef: 'encryption-key'
            }
            {
              name: 'JWT_SECRET_KEY'
              secretRef: 'secret-key'
            }
          ],
          !empty(azureAdTenantId) ? [
            {
              name: 'AZURE_AD_TENANT_ID'
              value: azureAdTenantId
            }
          ] : [],
          !empty(azureAdClientId) ? [
            {
              name: 'AZURE_AD_CLIENT_ID'
              value: azureAdClientId
            }
          ] : [],
          !empty(azureAdClientSecret) ? [
            {
              name: 'AZURE_AD_CLIENT_SECRET'
              secretRef: 'azure-ad-client-secret'
            }
          ] : [],
          !empty(frontendUrl) ? [
            {
              name: 'FRONTEND_URL'
              value: frontendUrl
            }
            {
              name: 'ALLOWED_ORIGINS'
              value: frontendUrl
            }
          ] : []
          )
          probes: useCustomImage ? [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 8000
              }
              initialDelaySeconds: 30
              periodSeconds: 30
              failureThreshold: 3
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/health'
                port: 8000
              }
              initialDelaySeconds: 10
              periodSeconds: 10
              failureThreshold: 3
            }
          ] : []
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
        rules: [
          {
            name: 'http-scaling'
            http: {
              metadata: {
                concurrentRequests: '50'
              }
            }
          }
        ]
      }
    }
  }
}

// --- Key Vault RBAC: Grant Container App managed identity access ---

resource kvRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, containerApp.id, '4633458b-17de-408a-b874-0445c86b69e6')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6') // Key Vault Secrets User
    principalId: containerApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ===========================================================================
// Storage Account (Frontend Static Files)
// ===========================================================================

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: take('frs${replace(environment, '-', '')}${uniqueSuffix}', 24)
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: {
    name: isProduction ? 'Standard_GRS' : 'Standard_LRS'
  }
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: true
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    cors: {
      corsRules: [
        {
          allowedOrigins: [
            '*'
          ]
          allowedMethods: [
            'GET'
            'HEAD'
            'OPTIONS'
          ]
          allowedHeaders: [
            '*'
          ]
          exposedHeaders: [
            '*'
          ]
          maxAgeInSeconds: 86400
        }
      ]
    }
  }
}

resource frontendContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: '$web'
  properties: {
    publicAccess: 'Blob'
  }
}

// ===========================================================================
// Azure Front Door for Frontend CDN
// ===========================================================================

resource frontDoorProfile 'Microsoft.Cdn/profiles@2024-02-01' = {
  name: '${resourcePrefix}-afd'
  location: 'global'
  tags: tags
  sku: {
    name: 'Standard_AzureFrontDoor'
  }
}

resource frontDoorEndpoint 'Microsoft.Cdn/profiles/afdEndpoints@2024-02-01' = {
  parent: frontDoorProfile
  name: '${resourcePrefix}-fe'
  location: 'global'
  tags: tags
  properties: {
    enabledState: 'Enabled'
  }
}

resource frontDoorOriginGroup 'Microsoft.Cdn/profiles/originGroups@2024-02-01' = {
  parent: frontDoorProfile
  name: 'storage-origin-group'
  properties: {
    loadBalancingSettings: {
      sampleSize: 4
      successfulSamplesRequired: 3
    }
    healthProbeSettings: {
      probePath: '/'
      probeRequestType: 'HEAD'
      probeProtocol: 'Https'
      probeIntervalInSeconds: 100
    }
  }
}

resource frontDoorOrigin 'Microsoft.Cdn/profiles/originGroups/origins@2024-02-01' = {
  parent: frontDoorOriginGroup
  name: 'storage-origin'
  properties: {
    hostName: replace(replace(storageAccount.properties.primaryEndpoints.web, 'https://', ''), '/', '')
    httpPort: 80
    httpsPort: 443
    originHostHeader: replace(replace(storageAccount.properties.primaryEndpoints.web, 'https://', ''), '/', '')
    priority: 1
    weight: 1000
    enabledState: 'Enabled'
  }
}

resource frontDoorRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2024-02-01' = {
  parent: frontDoorEndpoint
  name: 'default-route'
  properties: {
    originGroup: {
      id: frontDoorOriginGroup.id
    }
    supportedProtocols: [
      'Https'
    ]
    patternsToMatch: [
      '/*'
    ]
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
  }
  dependsOn: [
    frontDoorOrigin
  ]
}

// ===========================================================================
// Diagnostic Settings for Container App
// NOTE: Container Apps diagnostic log categories vary by region and API
// version. Configure diagnostics via Azure Portal after deployment if needed.
// The Container App Environment already sends logs to Log Analytics above.
// ===========================================================================

// ===========================================================================
// Outputs
// ===========================================================================

@description('Container App FQDN')
output containerAppUrl string = 'https://${containerApp.properties.configuration.ingress.fqdn}'

@description('Storage account static website URL')
output storageAccountUrl string = storageAccount.properties.primaryEndpoints.web

@description('CDN endpoint URL for frontend')
output cdnEndpointUrl string = 'https://${frontDoorEndpoint.properties.hostName}'

@description('ACR login server')
output acrLoginServer string = acr.properties.loginServer

@description('Key Vault name')
output keyVaultName string = keyVault.name

@description('PostgreSQL server FQDN')
output postgresServerFqdn string = postgresServer.properties.fullyQualifiedDomainName

@description('Log Analytics workspace ID')
output logAnalyticsWorkspaceId string = logAnalytics.properties.customerId

@description('Container App managed identity principal ID')
output containerAppPrincipalId string = containerApp.identity.principalId
