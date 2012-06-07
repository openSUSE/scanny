require "spec_helper"

module Scanny::Checks
  describe XssLoggerCheck do
    before :each do
      @runner = Scanny::Runner.new(XssLoggerCheck.new)
      @issue  = Scanny::Issue.new("scanned_file.rb", 1, :low, "XSS issue", 79)
    end

    it "reports \"logger(params[:password])\" correctly" do
      @runner.should check("logger(params[:password])").with_issue(@issue)
    end

    it "reports \"logger(\"\#{interpolation}\")\" correctly" do
      @runner.should check('logger("#{interpolation}")').with_issue(@issue)
    end
  end
end
