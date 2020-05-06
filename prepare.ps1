<#
.SYNOPSIS
Assists with preparing a Windows VM prior to calling kubeadm join

.DESCRIPTION
This script assists with joining a Windows node to a cluster.
- Downloads Kubernetes binaries (kubelet, kubeadm) at the version specified
- Registers wins as a service in order to run kube-proxy and cni as DaemonSets.
- Registers kubelet as an nssm service. More info on nssm: https://nssm.cc/

.PARAMETER KubernetesVersion
Kubernetes version to download and use

.EXAMPLE
PS> .\PrepareNode.ps1 -KubernetesVersion v1.17.0

#>

Param(
    [parameter(Mandatory = $true, HelpMessage="Kubernetes version to use")]
    [string] $KubernetesVersion
)
$ErrorActionPreference = 'Stop'

function DownloadFile($destination, $source) {
    Write-Host("Downloading $source to $destination")
    curl.exe --silent --fail -Lo $destination $source

    if (!$?) {
        Write-Error "Download $source failed"
        exit 1
    }
}

if (!$KubernetesVersion.StartsWith("v")) {
    $KubernetesVersion = "v" + $KubernetesVersion
}
Write-Host "Using Kubernetes version: $KubernetesVersion"
$global:Powershell = (Get-Command powershell).Source
$global:PowershellArgs = "-ExecutionPolicy Bypass -NoProfile"
$global:KubernetesPath = "$env:SystemDrive\k"
$global:NssmInstallDirectory = "$env:ProgramFiles\nssm"
$kubeletBinPath = "$global:KubernetesPath\kubelet.exe"

mkdir -force "$global:KubernetesPath"
$env:Path += ";$global:KubernetesPath"
[Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)

DownloadFile $kubeletBinPath https://dl.k8s.io/$KubernetesVersion/bin/windows/amd64/kubelet.exe
DownloadFile "$global:KubernetesPath\kubelet.exe" https://dl.k8s.io/$KubernetesVersion/bin/windows/amd64/kubelet.exe
DownloadFile "$global:KubernetesPath\kubeadm.exe" https://dl.k8s.io/$KubernetesVersion/bin/windows/amd64/kubeadm.exe
DownloadFile "$global:KubernetesPath\kubectl.exe" https://dl.k8s.io/$KubernetesVersion/bin/windows/amd64/kubectl.exe
DownloadFile "$global:KubernetesPath\kube-proxy.exe" https://dl.k8s.io/$KubernetesVersion/bin/windows/amd64/kube-proxy.exe
DownloadFile "$global:KubernetesPath\wins.exe" https://github.com/rancher/wins/releases/download/v0.0.4/wins.exe

# Create host network to allow kubelet to schedule hostNetwork pods
Write-Host "Creating Docker host network"
docker network create -d nat host

Write-Host "Registering wins service"
wins.exe srv app run --register
start-service rancher-wins

mkdir -force C:\var\log\kubelet
mkdir -force C:\var\lib\kubelet\etc\kubernetes
mkdir -force C:\etc\kubernetes\pki
New-Item -path C:\var\lib\kubelet\etc\kubernetes\pki -type SymbolicLink -value C:\etc\kubernetes\pki\

$StartKubeletFileContent = '$FileContent = Get-Content -Path "/var/lib/kubelet/kubeadm-flags.env"
$global:KubeletArgs = $FileContent.Trim("KUBELET_KUBEADM_ARGS=`"")

$netId = docker network ls -f name=host --format "{{ .ID }}"

if ($netId.Length -lt 1) {
    docker network create -d nat host
}'

Write-Host "Installing nssm"
$arch = "win32"
if ([Environment]::Is64BitOperatingSystem) {
    $arch = "win64"
}

mkdir -Force $global:NssmInstallDirectory
DownloadFile nssm.zip https://k8stestinfrabinaries.blob.core.windows.net/nssm-mirror/nssm-2.24.zip
tar C $global:NssmInstallDirectory -xvf .\nssm.zip --strip-components 2 */$arch/*.exe
Remove-Item -Force .\nssm.zip

$env:path += ";$global:NssmInstallDirectory"
$newPath = "$global:NssmInstallDirectory;" +
[Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::Machine)

[Environment]::SetEnvironmentVariable("PATH", $newPath, [EnvironmentVariableTarget]::Machine)

function Install-AwsKubernetesFlannel {
  param (
    [parameter(Mandatory=$true)] $InstallationDirectory,
    [parameter(Mandatory=$false)] $FlanneldVersion = "0.11.0",
    [parameter(Mandatory=$false)] $DownloadBranch = "master",
    [parameter(Mandatory=$false)] $DownloadDirectory = (Join-Path -Path (Get-Item Env:TEMP).Value -ChildPath "flannel")
  )

    New-Item -Path $DownloadDirectory -ItemType "directory"

    $GitHubMicrosoftSDNRepo = "github.com/Microsoft/SDN"
    $GitHubFlannelRepo = "github.com/coreos/flannel"

    # Download HNS Powershell module.
    wget "https://$GitHubMicrosoftSDNRepo/raw/$DownloadBranch/Kubernetes/windows/hns.psm1" `
      -OutFile "$InstallationDirectory/hns.psm1"

    # Install flanneld executable.
    wget "https://$GitHubFlannelRepo/releases/download/v$FlanneldVersion/flanneld.exe" `
      -OutFile "$InstallationDirectory/flanneld.exe"

    # Install CNI executables.
    New-Item -Path "$InstallationDirectory/cni" -ItemType "directory"
    wget "https://$GitHubMicrosoftSDNRepo/raw/$DownloadBranch/Kubernetes/flannel/l2bridge/cni/host-local.exe" `
      -OutFile "$InstallationDirectory/cni/host-local.exe"
    wget "https://$GitHubMicrosoftSDNRepo/raw/$DownloadBranch/Kubernetes/flannel/l2bridge/cni/flannel.exe" `
      -OutFile "$InstallationDirectory/cni/flannel.exe"
    wget "https://$GitHubMicrosoftSDNRepo/raw/$DownloadBranch/Kubernetes/flannel/overlay/cni/win-overlay.exe" `
      -OutFile "$InstallationDirectory/cni/win-overlay.exe"

    # Create directories needed for runtime.
    New-Item -Path "c:/etc/kube-flannel" -ItemType directory -ErrorAction Ignore
    New-Item -Path "c:/run/flannel" -ItemType directory -ErrorAction Ignore
    Remove-Item -Path $DownloadDirectory -Recurse
}

Install-AwsKubernetesFlannel -InstallationDirectory $global:KubernetesPath

$WindowsVersion = (Get-ComputerInfo).WindowsVersion
# Pull ready-made Windows containers of the given Windows version.
docker pull "mcr.microsoft.com/powershell:nanoserver-$WindowsVersion"
docker pull "mcr.microsoft.com/dotnet/framework/aspnet:4.8"
