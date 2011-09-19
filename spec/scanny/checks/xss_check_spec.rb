require "spec_helper"

module Scanny::Checks
  describe XssCheck do
    before :each do
      @runner = Scanny::Runner.new(XssCheck.new)
      @issue = Scanny::Issue.new("scanned_file.rb", 1, :high, "XSS issue", 79)
    end

    it "reports \"send_file :disposition => 'inline'\" correctly" do
      @runner.should check("send_file :disposition => 'inline' ").with_issue(@issue)
      @runner.should check("send_file :disposition => 'attachment' ").without_issues
    end

    it "reports \"send_data :disposition => 'inline'\" correctly" do
      @runner.should check("send_data :disposition => 'inline' ").with_issue(@issue)
      @runner.should check("send_data :disposition => 'attachment' ").without_issues
    end
  end
end
