require "spec_helper"

module Scanny::Checks
  describe XssCheck do
    before :each do
      @runner = Scanny::Runner.new(XssCheck.new)
    end

    it "does not report regular method calls" do
      @runner.should check('foo').without_issues
    end

    describe "inspect send_file" do
      it "reports issues when :disposition is set to inline" do
        @runner.should check("send_file :disposition => 'inline' ").with_issue(:high,
          "XSS issue")
      end

      it "does not report issues when :disposition is not set to inline" do
        @runner.should check("send_file :disposition => 'attachment' ").without_issues
      end
    end

    describe "inspect send_data" do
      it "reports issues when :disposition is set to inline" do
        @runner.should check("send_data :disposition => 'inline' ").with_issue(:high,
          "XSS issue")
      end

      it "does not report issues when :disposition is not set to inline" do
        @runner.should check("send_data :disposition => 'attachment' ").without_issues
      end
    end
  end
end
