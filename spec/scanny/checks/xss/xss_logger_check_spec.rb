require "spec_helper"

module Scanny::Checks
  describe XssLoggerCheck do
    before :each do
      @runner = Scanny::Runner.new(XssLoggerCheck.new)
      @warning_message = "Assigning request parameters into logger can lead to XSS issues."
      @issue  = Scanny::Issue.new("scanned_file.rb", 1, :low, @warning_message, [20, 79])
    end

    it "reports \"logger(\"User \#{params[:password]} log\") correctly" do
      @runner.should check('logger("User #{params[:password]} log")').with_issues(@issue)
    end

    it "reports \"logger(params[:password])\" correctly" do
      @runner.should check("logger(params[:password])").with_issue(@issue)
    end

    it "reports \"logger(\"\#{interpolation}\")\" correctly" do
      @runner.should check('logger("#{interpolation}")').with_issue(@issue)
    end
  end
end
