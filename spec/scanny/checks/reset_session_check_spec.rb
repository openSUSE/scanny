require "spec_helper"

module Scanny::Checks
  describe ResetSessionCheck do
    before do
      @runner = Scanny::Runner.new(ResetSessionCheck.new)
      @message = "Improper resetting the session may lead to security problems"
      @issue = issue(:info, @message, 384)
    end

    it "reports \"reset_session\" correctly" do
      @runner.should check("reset_session").with_issue(@issue)
    end
  end
end
