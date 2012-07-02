require "spec_helper"

module Scanny::Checks
  describe FrameworksCheck do
    before do
      @runner = Scanny::Runner.new(FrameworksCheck.new)
      @message = "Using the methods from frameworks can lead to security problems"
      @issue = issue(:info, @message, 0)
    end

    it "reports \"'string'.xss_safe\" correctly" do
      @runner.should check("'string'.xss_safe").with_issue(@issue)
    end

    it "reports \"'string'.mark_as_xss_protected\" correctly" do
      @runner.should check("'string'.mark_as_xss_protected").with_issue(@issue)
    end

    it "reports \"'string'.mark_methods_as_xss_safe\" correctly" do
      @runner.should check("'string'.mark_methods_as_xss_safe").with_issue(@issue)
    end

    it "reports \"'string'.to_s_xss_protected\" correctly" do
      @runner.should check("'string'.to_s_xss_protected").with_issue(@issue)
    end

    it "reports \"env['HTTP_X_USERNAME']\" correctly" do
      @runner.should check("env['HTTP_X_USERNAME']").with_issue(@issue)
    end

  end
end
