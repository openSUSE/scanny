require "spec_helper"

module Scanny::Checks
  describe XssSendCheck do
    before :each do
      @runner = Scanny::Runner.new(XssSendCheck.new)
      @warning_message = "Send file or data to client in \"inline\" mode can lead to XSS issues."
      @issue = Scanny::Issue.new("scanned_file.rb", 1, :high, @warning_message, 79)
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
