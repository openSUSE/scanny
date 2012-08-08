require "spec_helper"

module Scanny::Checks
  describe FrameworksCheck do
    before do
      @runner = Scanny::Runner.new(FrameworksCheck.new)
      @message = "Using the methods from frameworks can lead to security problems"
      @issue = issue(:info, @message)
    end

    it "reports \"env['HTTP_X_USERNAME']\" correctly" do
      @runner.should check("env['HTTP_X_USERNAME']").with_issue(@issue)
    end

  end
end
