require "spec_helper"

module Scanny::Checks
  describe InputFilteringCheck do
    before do
      @runner = Scanny::Runner.new(InputFilteringCheck.new)
      @message =  "Possible injection vulnerabilities"
      @issue = issue(:low, @message, 20)
    end

    it "reports \"logger(params[:password])\" correctly" do
      @runner.should check("params[:password]").with_issue(@issue)
    end

    it "reports \"env('HTTP_HEADER')\" correctly" do
      @runner.should check("env['HTTP_HEADER']").with_issue(@issue)
    end

    it "reports \"headers('HTTP_HEADER')\" correctly" do
      @runner.should check("headers['HTTP_HEADER']").with_issue(@issue)
    end
  end
end
