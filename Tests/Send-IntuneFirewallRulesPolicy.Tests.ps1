. "$PSScriptRoot\..\IntuneFirewallMigration\Public\Send-IntuneFirewallRulesPolicy.ps1"
. "$PSScriptRoot\..\IntuneFirewallMigration\Private\Strings.ps1"

Describe 'Send-IntuneFirewallRulesPolicy' {
    Context 'Empty base case' {
        It 'Should run nothing if given empty profiles' {
            Mock Invoke-MgGraphRequest
            @() | Send-IntuneFirewallRulesPolicy
            Assert-MockCalled Invoke-MgGraphRequest -Times 0
        }
    }

    Context 'Running with one profile' {
        It 'Should run Invoke-MgGraphRequest once if given 1 <= x <= 150' {
            Mock Invoke-MgGraphRequest
            @(1..10) | Send-IntuneFirewallRulesPolicy
            Assert-MockCalled Invoke-MgGraphRequest -Times 1 -Exactly
        }
    }

    Context 'Running with two profiles' {
        It 'Should run Invoke-MgGraphRequest twice if given 151 <= x <= 300' {
            Mock Invoke-MgGraphRequest
            @(1..151) | Send-IntuneFirewallRulesPolicy
            Assert-MockCalled Invoke-MgGraphRequest -Times 2 -Exactly
        }
    }

    Context 'Running with five profiles' {
        It 'Should run Invoke-MgGraphRequest 5 times' {
            Mock Invoke-MgGraphRequest
            @(1..(150 * 5)) | Send-IntuneFirewallRulesPolicy
            Assert-MockCalled Invoke-MgGraphRequest -Times 5 -Exactly
        }
    }
}