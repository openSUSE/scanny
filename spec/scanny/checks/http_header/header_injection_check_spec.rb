require "spec_helper"

module Scanny::Checks::HttpHeader
  describe HeaderInjectionCheck do
    before do
      @runner = Scanny::Runner.new(HeaderInjectionCheck.new)
      @message = "Directly use of the HTTP_* headers in code"
      @issue = issue(:medium, @message, [20, 113])
    end

    it "reports \"env['HTTP_HEADER']\" correctly" do
      @runner.should check("env['HTTP_HEADER']").with_issue(@issue)
    end

    it "reports \"headers['HTTP_HEADER']\" correctly" do
      @runner.should check("headers['HTTP_HEADER']").with_issue(@issue)
      @runner.should check("headers['NORMAL_HEADER']").without_issues
    end
  end
end
