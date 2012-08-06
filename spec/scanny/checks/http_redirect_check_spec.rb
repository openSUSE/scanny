require "spec_helper"

module Scanny::Checks
  describe HTTPRedirectCheck do
    before do
      @runner = Scanny::Runner.new(HTTPRedirectCheck.new)
      @message = "HTTP redirects can be emitted by the Application"
      @issue = issue(:medium, @message, 441)
    end

    it "reports \"require 'open-uri'\" correctly" do
      @runner.should check("require 'open-uri'").with_issue(@issue)
    end

    it "reports \"OpenStruct.new\" correctly" do
      @runner.should check("OpenStruct.new").with_issue(@issue)
    end

    it "reports \"OpenStruct.new(:key => :value)\" correctly" do
      @runner.should check("OpenStruct.new(:key => :value)").with_issue(@issue)
    end
  end
end
