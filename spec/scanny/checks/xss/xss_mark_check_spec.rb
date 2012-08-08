require "spec_helper"

module Scanny::Checks
  describe XssMarkCheck do
    before :each do
      @runner = Scanny::Runner.new(XssMarkCheck.new)
      @warning_message = "Marking string as safe can lead to XSS issues."
      @issue  = Scanny::Issue.new("scanned_file.rb", 1, :info, @warning_message)
    end

    it "reports \"'string'.xss_safe\" correctly" do
      @runner.should check("'string'.xss_safe").with_issue(@issue)
    end

    it "reports \"'string'.mark_as_xss_protected\" correctly" do
      @runner.should check("'string'.mark_as_xss_protected").with_issue(@issue)
    end

    it "reports \"'string'.mark_methods_as_xss_safe\" correctly" do
      @runner.should check("'string'.mark_methods_as_xss_safe").with_issue(@issue)
    end

    it "reports \"'string'.to_s_xss_protected\" correctly" do
      @runner.should check("'string'.to_s_xss_protected").with_issue(@issue)
    end
  end
end
