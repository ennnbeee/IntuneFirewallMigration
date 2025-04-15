# This file is a container for all user-visible strings in the project. The strings are grouped by their files.

data Strings {
    ConvertFrom-StringData -StringData @'
# ConvertTo-IntuneFirewallRule-Helper
FirewallRuleDisplayNameTooLongTitle=Found a firewall rule which needs some work
FirewallRuleDisplayNameTooLongMessage=The firewall rule name '{0}' is too long.\nWould you like to truncate this name? The displayName is shown below:\n{1}
FirewallRuleDisplayNameYes=Truncate the display name to {0} characters
FirewallRuleDisplayNameNo=Stop processing this firewall rule and raise an exception. You will be prompted to continue processing other firewall rules
FirewallRuleDisplayNameRename=Rename the firewall rule display name
FirewallRuleDisplayNameException=User did not continue processing display name
FirewallRuleDisplayName=DisplayName
FirewallRuleDisplayNameRenamePrompt=Enter new display name

FirewallRulePackageFamilyNameSidTitle=Found a firewall rule which needs some work
FirewallRulePackageFamilyNameSidMessage=The firewall rule '{0}' contains a package SID (Security Identifier) that is not recognized on your computer\n{1}\n{2}\n{3}
FirewallRulePackageFamilyNameUniqueName=Firewall rule unique name: {0}\n
FirewallRulePackageFamilyNameSid=Package SID (Security Identifier): {0}\n
FirewallRulePackageFamilyNameDescription=The SID (Security Identifier) is used by this tool to get the package family name of the app this rule applies to.\nWould you like to set the package family name?\nThe package family name can be found in Windows Defender Firewall with Advanced Security:\nSelect the firewall rule -> Programs and Services -> Application Packages
FirewallRulePackageFamilyNameYes=Rename the package family name
FirewallRulePackageFamilyNameNo=Stop processing this firewall rule and stop execution
FirewallRulePackageFamilyNamePrompt=Enter the new package family name
FirewallRulePackageFamilyNameException=Package family name was not found
FirewallRulePackageFamilyName=PackageFamilyName

FirewallRuleProtocolException=Encountered error when parsing protocol: {0}
FirewallRuleProtocol=Protocol

FirewallRuleLocalPort=LocalPort
FirewallRuleRemotePort=RemotePort
FirewallRulePortException=Encountered unexpected type when parsing port for firewall rule: {0}
FirewallRulePortRangeException=Encountered unexpected port range value when processing ports: {0}

FirewallRuleAddressRangePlayToDeviceException=PlayToDevice is not supported by Intune
FirewallRuleAddressRangeNoMatchException=The Address range {0} is not supported by Intune
FirewallRuleAddressRange=AddressRange

FirewallRuleProfileTypeException=Encountered unexpected profile type number: {0}
FirewallRuleProfileType=ProfileType

FirewallRuleActionAllowBypassException=The firewall rule action 'AllowByPass' is currently not supported by Intune
FirewallRuleActionException=Encountered unexpected firewall action '{0}' when parsing firewall rule action
FirewallRuleAction=Action

FirewallRuleDirectionException=Encountered unexpected direction '{0}' when mapping firewall rule direction
FirewallRuleDirection=Direction

FirewallRuleInterfaceTypeException=Encountered unexpected interface type '{0}' when parsing firewall rule interface types
FirewallRuleInterfaceType=InterfaceType

FirewallRuleEdgeTraversalException=Could not map edge traversal policy with direction '{0}' and edge policy '{1}'
FirewallRuleEdgeTraversal=EdgeTraversalPolicy

# Process-IntuneFirewallRules
SplitFirewallRuleTitle=Found a Firewall Rule which needs some work.
SplitFirewallRuleMessage=The Intune Graph API does not support firewall rules where PackageFamilyName, ServiceName, and FilePath are set at the same time.\n{0}\nA new firewall rule will be created for each non-empty property.\nWould you like to split the firewall rule into separate rules?
SplitFirewallRuleDisplayName=DisplayName: {0}\n
SplitFirewallRulePackageFamilyName=PackageFamilyName: {0}\n
SplitFirewallRuleFilePath=FilePath: {0}\n
SplitFirewallRuleServiceName=ServiceName: {0}\n
SplitFirewallRuleYes=Split the firewall rule
SplitFirewallRuleNo=Do not split the firewall rule and stop execution
SplitFirewallRuleYesToAll=Treat all other splits as 'Yes'
SplitFirewallRuleContinue=Do not split the firewall rule and continue processing other firewall rules. The current firewall rule will not be exported.

# Use-HelperFunctions
ShowOperationProgressException=Given non-positive total firewall rules
OperationStatus={0} / {1} | {2}% complete

# ConvertTo-IntuneFirewallRule
ConvertToIntuneFirewallRuleProgressMessage=Processing firewall rules
ConvertToIntuneFirewallRuleNoSplit=ConvertTo-IntuneFirewallRule stopped: User did not split firewall rule
ConvertToIntuneFirewallRuleNoException=User aborted error handling for ConvertTo-IntuneFirewallRule

# IntuneFirewallRule
NewIntuneFirewallRuleShouldProcessMessage=Creating new IntuneFirewallRule object

# Send-IntuneFirewallRulesPolicy
SendIntuneFirewallRulesPolicyProfileNameDefault=MigratedFirewallProfile
SendIntuneFirewallRulesPolicyProgressStatus=Importing profiles to Intune
SendIntuneFirewallRulesPolicyShouldSendData=Sending profile data to Intune
SendIntuneFirewallRulesPolicyException=User aborted error handling for Send-IntuneFirewallRulesPolicy

# Validate Profile Name
EnterProfile=Please enter a name for the Firewall Rules policy
ProfileExists=The policy name you provided already exists. Please enter a unique policy name
ProfileCannotBeBlank =The policy name field cannot be blank. Please enter a valid policy name

# General
Any=Any
Yes=Yes
No=No
YesToAll=Yes To All
Continue=Continue

# Graph Endpoints
GraphFirewallRulesEndpoint=https://graph.microsoft.com/beta/deviceManagement/intents?$filter=templateId%20eq%20%274b219836-f2b1-46c6-954d-4cd2f4128676%27%20or%20templateId%20eq%20%274356d05c-a4ab-4a07-9ece-739f7c792910%27%20or%20templateId%20eq%20%275340aa10-47a8-4e67-893f-690984e4d5da%27
'@
}