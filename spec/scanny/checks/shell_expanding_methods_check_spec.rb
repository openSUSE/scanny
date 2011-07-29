require "spec_helper"

module Scanny::Checks
  describe ShellExpandingMethodsCheck do
    before :each do
      @runner = Scanny::Runner.new(ShellExpandingMethodsCheck.new)
    end

    it "reports \"Kernel.`\" calls" do
      @runner.should parse('Kernel.` "ls -l"').with_issue(:high,
        "The \"`\" method passes the executed command through shell expansion. (CWE-88,CWE-78)")
    end

    it "does not report \"`\" calls on other classes/modules" do
      @runner.should parse('Foo.` "ls -l"').without_issues
    end

    it "does not report \"`\" calls on random objects" do
      @runner.should parse('foo.` "ls -l"').without_issues
    end

    it "reports \"exec\" calls without a receiver" do
      @runner.should parse('exec "ls -l"').with_issue(:high,
        "The \"exec\" method passes the executed command through shell expansion. (CWE-88,CWE-78)")
    end

    it "reports \"Kernel.exec\" calls" do
      @runner.should parse('Kernel.exec "ls -l"').with_issue(:high,
        "The \"exec\" method passes the executed command through shell expansion. (CWE-88,CWE-78)")
    end

    it "does not report \"exec\" calls on other classes/modules" do
      @runner.should parse('Foo.exec "ls -l"').without_issues
    end

    it "does not report \"exec\" calls on random objects" do
      @runner.should parse('foo.exec "ls -l"').without_issues
    end

    it "reports \"system\" calls without a receiver" do
      @runner.should parse('system "ls -l"').with_issue(:high,
        "The \"system\" method passes the executed command through shell expansion. (CWE-88,CWE-78)")
    end

    it "reports \"Kernel.system\" calls" do
      @runner.should parse('Kernel.system "ls -l"').with_issue(:high,
        "The \"system\" method passes the executed command through shell expansion. (CWE-88,CWE-78)")
    end

    it "does not report \"system\" calls on other classes/modules" do
      @runner.should parse('Foo.system "ls -l"').without_issues
    end

    it "does not report \"system\" calls on random objects" do
      @runner.should parse('foo.system "ls -l"').without_issues
    end

    it "does not report calls with no arguments" do
      @runner.should parse('exec').without_issues
    end

    it "reports calls with one argument" do
      @runner.should parse('exec "ls -l"').with_issue(:high,
        "The \"exec\" method passes the executed command through shell expansion. (CWE-88,CWE-78)")
    end

    it "does not report calls with multiple arguments" do
      @runner.should parse('exec "ls", "-l"').without_issues
    end
  end
end
