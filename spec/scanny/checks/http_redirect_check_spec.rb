require "spec_helper"

module Scanny::Checks
  describe HTTPRedirectCheck do
    before do
      @runner = Scanny::Runner.new(HTTPRedirectCheck.new)
      @message = "HTTP redirects can be emitted by the Application"
      @issue_441 = issue(:medium, @message, 441)
      @issue = issue(:medium, @message, [601, 698, 79])
    end

    it "reports \"redirect_to params[:to]\" correctly" do
      @runner.should check("redirect_to params[:to]").with_issue(@issue)
    end

    it "reports \"require 'open-uri'\" correctly" do
      @runner.should check("require 'open-uri'").with_issue(@issue_441)
    end

    it "reports \"save_file\" correctly" do
      @runner.should check("save_file").with_issue(@issue_441)
    end

    it "reports \"save_file(file)\" correctly" do
      @runner.should check("save_file(file)").with_issue(@issue_441)
    end

    it "reports \"add_file_from_url(url)\" correctly" do
      @runner.should check("add_file_from_url(url)").with_issue(@issue_441)
    end

    it "reports \"OpenStruct.new\" correctly" do
      @runner.should check("OpenStruct.new").with_issue(@issue_441)
    end

    it "reports \"OpenStruct.new(:key => :value)\" correctly" do
      @runner.should check("OpenStruct.new(:key => :value)").with_issue(@issue_441)
    end
  end
end
