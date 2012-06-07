require "spec_helper"

module Scanny::Checks
  describe XssMarkCheck do
    before :each do
      @runner = Scanny::Runner.new(XssMarkCheck.new)
      @issue  = Scanny::Issue.new("scanned_file.rb", 1, :info, "XSS issue", 0)
    end

    it "reports \"mark_as_xss_protected\" correctly" do
      @runner.should check("mark_as_xss_protected").with_issue(@issue)
    end

    it "reports \"mark_methods_as_xss_safe\" correctly" do
      @runner.should check('mark_methods_as_xss_safe').with_issue(@issue)
    end
  end
end
