require "spec_helper"

module Scanny::Checks
  describe XssSendCheck do
    before :each do
      @runner = Scanny::Runner.new(XssSendCheck.new)
      @warning_message =  "Send file or data to client in \"inline\" " +
                          "mode or with param can lead to XSS issues."
      @issue = Scanny::Issue.new("scanned_file.rb", 1, :medium, @warning_message, [79, 115, 200])
      @issue_201 = Scanny::Issue.new("scanned_file.rb", 1, :high, @warning_message, 201)
    end

    it "reports \"send_file :disposition => 'inline'\" correctly" do
      @runner.should check("send_file 'file', :disposition => 'inline'").with_issue(@issue)
      @runner.should check("send_file 'file', :disposition => 'attachment'").without_issues
    end

    it "reports \"send_data :disposition => 'inline'\" correctly" do
      @runner.should check("send_data 'file', :disposition => 'inline'").with_issue(@issue)
      @runner.should check("send_data 'file', :disposition => 'attachment'").without_issues
    end

    it "reports \"send_data file :type => 'image/jpeg', :disposition => 'inline'\" correctly" do
      @runner.should
        check("send_data 'file', :type => 'image/jpeg', :disposition => 'inline'").
        with_issue(@issue)
    end

    it "reports \"send_(data|file) file, params[:file]\" correctly" do
      @runner.should check("send_data file, params[:file]").with_issue(@issue_201)
      @runner.should check("send_file file, params[:file]").with_issue(@issue_201)
    end
  end
end
