require "spec_helper"

module Scanny::Checks
  describe HTTPBasicAuthCheck do
    before do
      @runner = Scanny::Runner.new(HTTPBasicAuthCheck.new)
      @message = "Basic HTTP authentication can lead to security problems"
      @issue = issue(:info, @message, [301, 718])
    end

    it "reports \"Net::HTTPHeader#basic_auth'\" correctly" do
      @runner.should check("basic_auth('user', 'password')").with_issue(@issue)
      @runner.should check("basic_auth").without_issues
    end

    it "reports \"HttpAuthentication\" correctly" do
      @runner.should check("HttpAuthentication").with_issue(@issue)
    end
  end
end
