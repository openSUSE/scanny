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
  end
end
