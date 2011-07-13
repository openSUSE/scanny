require 'spec_helper'

module Scanny::Checks
  describe XssCheck do
    before :each do
      @scanny = Scanny::Runner.new(XssCheck.new)
    end

    it "does not report regular method calls" do
      @scanny.should parse('foo').without_issues
    end

    it "find issues caused by send_file when :disposition is :inline" do
      @scanny.should parse("send_file :disposition => :inline").with_issue(:high,
        "XSS issue")
    end
  end
end
