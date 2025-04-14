#
# Module manifest for module 'IntuneFirewallMigration'
#
# Generated by: t-kehui
#
# Generated on: 7/9/2019 1:31:54 PM
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'FirewallRuleMigration.psm1'

# Version number of this module.
ModuleVersion = '1.0'

# ID used to uniquely identify this module
GUID = 'c2f80199-864d-4dec-8c16-ed4952f8853c'

# Author of this module
Author = 'Kevin Hui, Tessy Emadoye, Nick Benton'

# Company or vendor of this module
CompanyName = 'Microsoft, oddsandendpoints.co.uk'

# Copyright statement for this module
Copyright = '(c) 2019 Microsoft. All rights reserved.'

# Description of the functionality provided by this module
Description = 'PowerShell cmdlet suite to support automation of migrating Windows firewall rules to Microsoft Intune'

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @("Microsoft.Graph.Authentication", "ImportExcel")

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module
# FunctionsToExport = 'Get-Function'

# Cmdlets to export from this module
CmdletsToExport = @('Get-SampleFirewallData','Export-NetFirewallRule', 'Send-IntuneFirewallRulesPolicy', 'ConvertTo-IntuneFirewallRule', 'New-IntuneFirewallRule')

# Variables to export from this module
# VariablesToExport = '*'

# Aliases to export from this module
# AliasesToExport = ''

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess
# PrivateData = ''

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}