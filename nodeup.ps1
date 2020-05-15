# Define some of our constants.
$global:progressPreference = 'silentlyContinue'
$AWSSelfServiceUri = "169.254.169.254/latest"
$KubernetesDirectory = "c:/k"
$KopsConfigBaseRegex = "^ConfigBase: s3://(?<bucket>[^/]+)/(?<prefix>.+)$"

########################################################################################################################
# Conveinence Functions
########################################################################################################################
function Get-AwsTag($TagName) { return ($script:Ec2Tags | Where-Object {$_.Key -eq "$TagName"}) }

########################################################################################################################
# Installation Functions
########################################################################################################################

function New-KubernetesConfigurations {
  param (
    [parameter(Mandatory=$true)] $DestinationBaseDir,
    [parameter(Mandatory=$true)] $KopsStateStoreBucket,
    [parameter(Mandatory=$true)] $KopsStateStorePrefix,
    [parameter(Mandatory=$true)] $KubernetesMasterInternalName,
    [parameter(Mandatory=$false)] [string[]] $KubernetesUsers
  )

  # Download the issued certificate authority keyset.
  New-Item $DestinationBaseDir/issued/ca -ItemType Directory -ErrorAction SilentlyContinue
  $S3ObjectKey = "$KopsStateStorePrefix/pki/issued/ca/keyset.yaml"
  $LocalCertificateAuthorityFile = "$DestinationBaseDir/ca-keyset.yaml"
  Read-S3Object -BucketName $KopsStateStoreBucket -Key $S3ObjectKey -File $LocalCertificateAuthorityFile

  # Load the certificate authority data.
  $CertificateAuthorityData = ((Get-Content $LocalCertificateAuthorityFile) | ConvertFrom-Yaml).spec.keys[0]
  $CertificateAuthorityCertificate = [System.Convert]::FromBase64String($CertificateAuthorityData.publicMaterial)
  Set-Content -Path $DestinationBaseDir/issued/ca.crt -Value $CertificateAuthorityCertificate -Encoding Byte
  foreach($KubernetesUser in $KubernetesUsers) {
    Write-Host "generating kubeconfig for $KubernetesUser"

    # Download each user's secrets.
    New-Item $DestinationBaseDir/private/$KubernetesUser -ItemType Directory -ErrorAction SilentlyContinue
    $S3ObjectKey = "$KopsStateStorePrefix/pki/private/$KubernetesUser/keyset.yaml"
    $LocalUserFile = "$DestinationBaseDir/$KubernetesUser-keyset.yaml"
    Read-S3Object -BucketName $KopsStateStoreBucket -Key $S3ObjectKey -File $LocalUserFile

    # Load the user's secrets.
    $KuberenetesUserData = ((Get-Content $LocalUserFile) | ConvertFrom-Yaml).spec.keys[0]

    # Generate the Kubernetes configuration file for each user.
    $KubernetesConfigData = @{
      "apiVersion"="v1";
      "clusters"=@(
          @{
              "cluster"=@{
                  "certificate-authority-data"=$CertificateAuthorityData.publicMaterial;
                  "server"="https://$KubernetesMasterInternalName";
              };
              "name"="local";
          }
      );
      "contexts"=@(
          @{
              "context"=@{
                  "cluster"="local";
                  "user"="$KubernetesUser";
              };
              "name"="service-account-context";
          }
      )
      "current-context"="service-account-context";
      "kind"="Config";
      "users"=@(
          @{
              "name"="$KubernetesUser";
              "user"=@{
                  "client-certificate-data"=$KuberenetesUserData.publicMaterial;
                  "client-key-data"=$KuberenetesUserData.privateMaterial;
              };
          }
      );
    }
    
    ConvertTo-Yaml $KubernetesConfigData | Set-Content -Path "$DestinationBaseDir/$KubernetesUser.kcfg"
    Remove-Item -Path $LocalUserFile -Force
  }
  Remove-Item -Path $LocalCertificateAuthorityFile -Force
}


function Get-NodeKeysetFromTags {
  param(
    [parameter(Mandatory=$true)] $Prefix,
    [parameter(Mandatory=$false)] $Tags = $script:Ec2Tags
  )

  $tags = $script:Ec2Tags
  $tags = $Tags | Where-Object { $_.Key -like "$Prefix/*" } | ForEach-Object {
    return $_.Key.replace("$Prefix/", "") + "=" + $_.Value
  }
  return $tags
}

function Get-NodeLabelsFromTags {
  param(
    [parameter(Mandatory=$false)] $Prefix = "k8s.io/cluster-autoscaler/node-template/label",
    [parameter(Mandatory=$false)] $Tags = $script:Ec2Tags
  )
  return (Get-NodeKeysetFromTags -Prefix $Prefix -Tags $Tags)
}

function Get-NodeTaintsFromTags {
  param(
    [parameter(Mandatory=$false)] $Prefix = "k8s.io/cluster-autoscaler/node-template/taint",
    [parameter(Mandatory=$false)] $Tags = $script:Ec2Tags
  )
  return (Get-NodeKeysetFromTags -Prefix $Prefix -Tags $Tags)
}

function Update-NetConfigurationFile {
  param(
    [parameter(Mandatory=$false)] $NetworkName = "vxlan0",
    [parameter(Mandatory=$false)] $NetworkMode = "vxlan",
    [parameter(Mandatory=$false)] $KubeClusterCidr = $env:KubeClusterCidr
  )

  $NetConfigurationFile = "c:/etc/kube-flannel/net-conf.json"

  $Configuration = @{
    "Network"="$KubeClusterCidr"
    "Backend"=@{
      "name"="$NetworkName"
      "type"="$NetworkMode"
    }
  }

  if(Test-Path $NetConfigurationFile) {
    Clear-Content -Path $NetConfigurationFile
  }

  Write-Host "Generated net-conf.json Config [$Configuration]"
  Add-Content -Path $NetConfigurationFile -Value (ConvertTo-Json $Configuration)
}

function Update-CniConfigurationFile {
  param(
    [parameter(Mandatory=$false)] $KubernetesDirectory = $script:KubernetesDirectory,
    [parameter(Mandatory=$false)] $NetworkName = "vxlan0",
    [parameter(Mandatory=$false)] $KubeDnsSuffix = "svc.cluster.local",
    [parameter(Mandatory=$false)] $KubeClusterCidr = $env:KubeClusterCidr,
    [parameter(Mandatory=$false)] $KubeServiceCidr = $env:KubeServiceCidr,
    [parameter(Mandatory=$false)] $KubeClusterDns = $env:KubeClusterDns
  )

  New-Item -Path "$KubernetesDirectory/cni/config" -ItemType directory
  $CniConfigurationFile = "$KubernetesDirectory/cni/config/cni.conf"

  $Configuration = @{
    "cniVersion"="0.2.0"
    "name"="$NetworkName"
    "type"="flannel"
    "delegate"=@{
      "type"="win-overlay"
      "dns"=@{
        "Nameservers"=@(
          "$KubeClusterDns"
        )
        "Search"=@(
          "$KubeDnsSuffix"
        )
      }
      "policies"=@(
        @{
          "Name"="EndpointPolicy"
          "Value"=@{
            "Type"="OutBoundNAT"
            "ExceptionList"=@(
              $KubeClusterCidr,
              $KubeServiceCidr
              )
          }
        },
        @{
          "Name"="EndpointPolicy"
          "Value"=@{
            "Type"="ROUTE"
            "DestinationPrefix"=$KubeClusterCidr
            "NeedEncap"=$true
          }
        }
      )
    }
  }

  if(Test-Path $CniConfigurationFile) {
    Clear-Content -Path $CniConfigurationFile
  }

  Write-Host "Generated CNI Config [$Configuration]"
  Add-Content -Path $CniConfigurationFile -Value (ConvertTo-Json $Configuration -Depth 20)
}

function Get-SourceVip {
  param(
    [parameter(Mandatory=$true)] $IpAddress,
    [parameter(Mandatory=$false)] $NetworkName = "vxlan0",
    [parameter(Mandatory=$false)] $KubernetesDirectory = $script:KubernetesDirectory
  )

  $hnsNetwork = Get-HnsNetwork | ? Name -eq $NetworkName.ToLower()
  $subnet = $hnsNetwork.Subnets[0].AddressPrefix

  $IpamConfig = @{
    "cniVersion"="0.2.0"
    "name"="$NetworkName"
    "ipam"=@{
      "type"="host-local"
      "ranges"=@(,
        @(,
          @{"subnet"="$subnet"}
        )
      )
    }
  }

  $env:CNI_COMMAND="ADD"
  $env:CNI_CONTAINERID="dummy"
  $env:CNI_NETNS="dummy"
  $env:CNI_IFNAME="dummy"
  $env:CNI_PATH="$KubernetesDirectory/cni" #path to host-local.exe

  $SourceVip = ($IpamConfig | ConvertTo-Json -Depth 20 | host-local.exe | ConvertFrom-Json).ip4.ip.Split("/")[0]

  Remove-Item env:CNI_COMMAND
  Remove-Item env:CNI_CONTAINERID
  Remove-Item env:CNI_NETNS
  Remove-Item env:CNI_IFNAME
  Remove-Item env:CNI_PATH

  return $SourceVip
}

function ConvertTo-AppParameters {
  param(
    [parameter(Mandatory=$true)] $AppParameters
  )

  $parameters = @()
  foreach($v in $AppParameters.GetEnumerator()) {
    $parameters += "--$($v.Name)=$($v.Value)"
  }

  return ($parameters -Join " ")
}

#### SCRIPT START ####
if(Test-Path -path C:\complete) { exit }

# Intialize Networking
# Acquire additional network information for a later stage.
$NetworkDefaultInterface = (
  Get-NetIPConfiguration | 
  Where-Object {
    $_.IPv4DefaultGateway -ne $null -and
    $_.NetAdapter.Status -ne "Disconnected"
  }
)
$NetworkDefaultGateway = $NetworkDefaultInterface.IPv4DefaultGateway.NextHop
$NetworkHostIpAddress = $NetworkDefaultInterface.IPv4Address.IPAddress
$env:NetworkHostIpAddress = $NetworkHostIpAddress

route ADD 169.254.169.254 MASK 255.255.255.255 $NetworkDefaultGateway /p

# Pull down our instance's tags.
$InstanceId = (wget "http://$script:AWSSelfServiceUri/meta-data/instance-id" -UseBasicParsing).Content
$Ec2Tags = (Get-EC2Tag -Filter @{ Name="resource-id"; Values="$InstanceId" })

# Start by obtaining information about our machine.
$ComputerInfo = (Get-ComputerInfo)

# Install a Powershell YAML module.
Start-Job -Name "yaml-install" -ScriptBlock { Install-Module powershell-yaml -Force }

# Pull a few variables from AWS' self-service URI.
$AwsRegion = ((wget "http://$script:AWSSelfServiceUri/dynamic/instance-identity/document" -UseBasicParsing).Content | ConvertFrom-Json).region
$env:NODE_NAME = (wget "http://$script:AWSSelfServiceUri/meta-data/local-hostname" -UseBasicParsing).Content

# Extract our kops configuration base from the user-data.
$KopsUserDataFile = "c:/userdata.txt"
$KopsUserData = (wget "http://$script:AWSSelfServiceUri/user-data" -UseBasicParsing).Content
$KopsUserData = [System.Text.Encoding]::ASCII.GetString($KopsUserData)
Set-Content -Path $KopsUserDataFile -Value $KopsUserData
$KopsConfigBase = (Get-Content $KopsUserDataFile | Select-String -Pattern $KopsConfigBaseRegex -AllMatches).Matches.Groups
Remove-Item -Path $KopsUserDataFile

# Store kops S3 backend config information from the userdata.
$KopsStateStoreBucket = ($KopsConfigBase | ? Name -eq "bucket").Value
$KopsStateStorePrefix = ($KopsConfigBase | ? Name -eq "prefix").Value

# Prepare our environment path.
$env:PATH += ";$KubernetesDirectory"
$env:PATH += ";$KubernetesDirectory/cni"
[System.Environment]::SetEnvironmentVariable('PATH', $env:PATH, [System.EnvironmentVariableTarget]::Machine)

$KopsClusterSpecificationFile = "$KubernetesDirectory/cluster.spec"

# Download the cluster specification from the kops S3 backend.
Read-S3Object `
  -BucketName "$KopsStateStoreBucket" `
  -Key "$KopsStateStorePrefix/cluster.spec" `
  -File $KopsClusterSpecificationFile

Get-Job -Name "yaml-install" | Wait-Job
Import-Module powershell-yaml

# Parse the YAML cluster specification file into a PowerShell object and remove the file.
$KopsClusterSpecification = (Get-Content $KopsClusterSpecificationFile | ConvertFrom-Yaml 2>&1).spec
Remove-Item -Path $KopsClusterSpecificationFile -Force

# Extract all necessary configuration items regarding the cluster.
$KubeClusterCidr = ($KopsClusterSpecification.nonMasqueradeCIDR | Sort-Object -Unique)
$KubeClusterDns = ($KopsClusterSpecification.kubelet.clusterDNS | Sort-Object -Unique)
$KubeClusterInternalApi = ($KopsClusterSpecification.masterInternalName | Sort-Object -Unique)
$KubeDnsDomain = ($KopsClusterSpecification.clusterDnsDomain | Sort-Object -Unique)
$KubeServiceCidr = "100.96.0.0/11"
$KubernetesVersion = ($KopsClusterSpecification.kubernetesVersion | Sort-Object -Unique)

# Download Kubernetes configuration files for both the kubelet and kube-proxy users.
New-KubernetesConfigurations `
  -DestinationBaseDir "$KubernetesDirectory/kconfigs" `
  -KopsStateStoreBucket $KopsStateStoreBucket `
  -KopsStateStorePrefix $KopsStateStorePrefix `
  -KubernetesMasterInternalName $KubeClusterInternalApi `
  -KubernetesUsers kubelet,kube-proxy

# Download the pre-made flannel ServiceAccount Kubernetes configuaration file.
Read-S3Object `
  -BucketName "$KopsStateStoreBucket" `
  -Key "$KopsStateStorePrefix/serviceaccount/flannel.kcfg" `
  -File "$KubernetesDirectory/kconfigs/flannel.kcfg"

# Wait for all installation jobs to finish.
Get-Job | Wait-Job

# Save all important pieces of information to the environment.
$env:AwsRegion = $AwsRegion
$env:KubeClusterCidr = $KubeClusterCidr
$env:KubeClusterDns = $KubeClusterDns
$env:KubeClusterInternalApi = $KubeClusterInternalApi
$env:KubeDnsDomain = $KubeDnsDomain
$env:KubeServiceCidr = $KubeServiceCidr

# Get taints and role from the cluster specification.
#$NodeTaints = @(Get-NodeTaintsFromTags)
#$NodeLabels = @(Get-NodeLabelsFromTags)

# Add our own labels and taints.
$NodeLabels += @(
  "beta.kubernetes.io/os=windows",
  "node.kubernetes.io/exclude-from-external-load-balancers=1"
)

$NodeTaints += @(
  "beta.kubernetes.io/os=windows:NoSchedule"
)

# Initially mark the node with NotReady taint.
$NodeTaints += @("node.kubernetes.io/NotReady=:NoSchedule")

# Join labels and taints into a single string.
$NodeTaints = $NodeTaints -Join ""","""
$NodeLabels = $NodeLabels -Join ""","""
$NodeTaints = """$NodeTaints"""
$NodeLabels = """$NodeLabels"""

# Go ahead install Docker credentials for AWS.
$env:DOCKER_CONFIG = "c:/.docker"
New-Item -Path $env:DOCKER_CONFIG -ItemType directory
Invoke-Expression -Command (Get-ECRLoginCommand -Region $env:AwsRegion).Command
[System.Environment]::SetEnvironmentVariable('DOCKER_CONFIG', $env:DOCKER_CONFIG, [System.EnvironmentVariableTarget]::Machine)

########################################################################################################################
# (3) Careful Execution of Kubernetes Executables and Networking
########################################################################################################################
Import-Module "$KubernetesDirectory/hns.psm1"

# Get the name of the flannel overlap network.
#$FlannelConfigMap = (kubectl --kubeconfig="$KubernetesDirectory/kconfigs/flannel.kcfg" get configmaps -n kube-system kube-flannel-cfg -ojson | ConvertFrom-Json)
#$FlannelCniConfiguration = ($FlannelConfigMap.data.'cni-conf.json' | ConvertFrom-Json)
$env:KUBE_NETWORK = "vxlan0"

# Create an overlay network to trigger a vSwitch creation.
# Do this only once as it causes network blip.
New-NetFirewallRule `
  -Name OverlayTraffic4789UDP `
  -Description "Overlay network traffic UDP" `
  -Action Allow `
  -LocalPort 4789 `
  -Enabled True `
  -DisplayName "Overlay Traffic 4789 UDP" `
  -Protocol UDP `
  -ErrorAction SilentlyContinue
if(!(Get-HnsNetwork | ? Name -eq "External")) {
  New-HNSNetwork `
    -Name "External" `
    -Type "overlay" `
    -AddressPrefix "192.168.255.0/30" `
    -Gateway "192.168.255.1" `
    -SubnetPolicies @(@{ Type = "VSID"; VSID = 9999; }) `
    -Verbose
}

# Open up the port for shell and logs.
New-NetFirewallRule `
  -Name OverlayTraffic10250UDP `
  -Description "Overlay network traffic TCP" `
  -Action Allow `
  -LocalPort 10250 `
  -Enabled True `
  -DisplayName "Overlay Traffic 10250 TCP" `
  -Protocol TCP `
  -ErrorAction SilentlyContinue

# Readd the static route to the metadata service.
route ADD 169.254.169.254 MASK 255.255.255.255 $NetworkDefaultGateway /p

# Wait for the network to stabilize, usually takes about five to ten seconds.
kubectl get nodes --kubeconfig="$KubernetesDirectory/kconfigs/kubelet.kcfg" 2>&1 | Out-Null
while($? -eq $false) {
  Start-Sleep 1
  # Use `kubectl get nodes` to just test the connectivity to the cluster.
  kubectl get nodes --kubeconfig="$KubernetesDirectory/kconfigs/kubelet.kcfg" 2>&1 | Out-Null
}

Update-NetConfigurationFile
Update-CniConfigurationFile

Update-NetConfigurationFile
Update-CniConfigurationFile

$Services = @("flanneld", "kubelet", "kube-proxy")
foreach($Service in $Services) {
  # Install our base services.
  nssm install $Service "$KubernetesDirectory/$Service"

  # Setup logging for each service.
  nssm set $Service AppStderr (Join-Path -Path "c:/" -ChildPath "$Service.log")
}

# Set service dependencies.
nssm set kube-proxy DependOnService kubelet flanneld

# Determine environment for the services.
nssm set flanneld AppEnvironmentExtra NODE_NAME=$env:NODE_NAME
nssm set kube-proxy AppEnvironmentExtra KUBE_NETWORK=$env:KUBE_NETWORK

# Determine our base arguments for the services.
$KubeletArguments = @{
  "anonymous-auth"="false";
  "authorization-mode"="Webhook";
  "cgroups-per-qos"="false";
  "client-ca-file"="$KubernetesDirectory/kconfigs/issued/ca.crt";
  "cloud-provider"="aws";
  "cluster-dns"="$env:KubeClusterDns";
  "cluster-domain"="$env:KubeDnsDomain";
  "cni-bin-dir"="$KubernetesDirectory/cni";
  "cni-conf-dir"="$KubernetesDirectory/cni/config";
  "enable-debugging-handlers"="true";
  "enforce-node-allocatable"="";
  "feature-gates"="""WinOverlay=true""";
  "hairpin-mode"="promiscuous-bridge";
  "hostname-override"="$env:NODE_NAME";
  "image-pull-progress-deadline"="20m";
  "kubeconfig"="$KubernetesDirectory/kconfigs/kubelet.kcfg";
  "network-plugin"="cni";
  "node-ip"="$NetworkHostIpAddress";
  "node-labels"="$NodeLabels";
  "non-masquerade-cidr"="$env:KubeClusterCidr";
  "pod-infra-container-image"="mcr.microsoft.com/oss/kubernetes/pause:1.3.0";
  "register-schedulable"="true";
  "register-with-taints"="$NodeTaints";
  "resolv-conf"="";
  "v"="6"
}

$FlannelArguments = @{
  "iface"="$NetworkHostIpAddress";
  "ip-masq"="1";
  "kubeconfig-file"="$KubernetesDirectory/kconfigs/flannel.kcfg";
  "kube-subnet-mgr"="1"
}

$KubeProxyArguments = @{
  "v"="4";
  "cluster-cidr"="$env:KubeServiceCidr";
  "enable-dsr"="false";
  "feature-gates"="""WinOverlay=true""";
  "hostname-override"="$env:NODE_NAME";
  "kubeconfig"="$KubernetesDirectory/kconfigs/kube-proxy.kcfg";
  "network-name"="$env:KUBE_NETWORK";
  "proxy-mode"="kernelspace";
  "source-vip"="$null"
}
nssm set kubelet AppParameters (ConvertTo-AppParameters -AppParameters $KubeletArguments)
nssm set flanneld AppParameters (ConvertTo-AppParameters -AppParameters $FlannelArguments)
nssm set kube-proxy AppParameters (ConvertTo-AppParameters -AppParameters $KubeProxyArguments)

# Start kubelet so that we register the node, but it won't be schedulable yet.
nssm start kubelet

# Start flannel so we can get the source VIP needed for kube-proxy.
nssm start flanneld

# We need to wait for a few seconds for flannel to start before we can get our source VIP.
# Ideally we'd have a way to check without having to poll, but as far as I can tell there's no way to tell if flannel
# is ready, aside from maybe parsing logs so this'll have to do.
Start-Sleep 5
while($SourceVip -eq $null) {
  Write-Host "attempting to get source-VIP"
  $SourceVip = Get-SourceVip -IpAddress $NetworkHostIpAddress -KubernetesDirectory $KubernetesDirectory
  Start-Sleep 1
}
Write-Host "obtained source-VIP"

$KubeProxyArguments.'source-vip' = "$SourceVip"
nssm set kube-proxy AppParameters (ConvertTo-AppParameters -AppParameters $KubeProxyArguments)

# Clear the HNS policy list before starting kube-proxy.
Get-HnsPolicyList | Remove-HnsPolicyList
nssm start kube-proxy

# Remove the NotReady taint so that pods can be scheduled.
kubectl --kubeconfig="$KubernetesDirectory/kconfigs/kubelet.kcfg" taint nodes $env:NODE_NAME "node.kubernetes.io/NotReady-"

# Mark our machine as being fully ready.
New-Item -Path C:\ -Name "complete" -ItemType "file" -Value "Finished initialization"