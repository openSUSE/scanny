require 'spec_helper'

module Scanny::Checks
  describe ShellExpansionCheck do
    before :each do
      @scanny = Scanny::Runner.new(ShellExpansionCheck.new)
    end

    it "does not report regular method calls" do
      @scanny.should parse('foo').without_issues
    end

    describe "reported methods" do
      it "reports \"Kernel.`\" calls" do
        @scanny.should parse('Kernel.` "ls -l"').with_issue(:high,
          "The \"`\" method can pass the executed command through shell exapnsion.")
      end

      it "does not report \"`\" calls on other classes/modules" do
        @scanny.should parse('Foo.` "ls -l"').without_issues
      end

      it "does not report \"`\" calls on random objects" do
        @scanny.should parse('foo.` "ls -l"').without_issues
      end

      it "reports \"exec\" calls without a receiver" do
        @scanny.should parse('exec "ls -l"').with_issue(:high,
          "The \"exec\" method can pass the executed command through shell exapnsion.")
      end

      it "reports \"Kernel.exec\" calls" do
        @scanny.should parse('Kernel.exec "ls -l"').with_issue(:high,
          "The \"exec\" method can pass the executed command through shell exapnsion.")
      end

      it "does not report \"exec\" calls on other classes/modules" do
        @scanny.should parse('Foo.exec "ls -l"').without_issues
      end

      it "does not report \"exec\" calls on random objects" do
        @scanny.should parse('foo.exec "ls -l"').without_issues
      end

      it "reports \"system\" calls without a receiver" do
        @scanny.should parse('system "ls -l"').with_issue(:high,
          "The \"system\" method can pass the executed command through shell exapnsion.")
      end

      it "reports \"Kernel.system\" calls" do
        @scanny.should parse('Kernel.system "ls -l"').with_issue(:high,
          "The \"system\" method can pass the executed command through shell exapnsion.")
      end

      it "does not report \"system\" calls on other classes/modules" do
        @scanny.should parse('Foo.system "ls -l"').without_issues
      end

      it "does not report \"system\" calls on random objects" do
        @scanny.should parse('foo.system "ls -l"').without_issues
      end
    end

    describe "argument counts" do
      it "does not report calls with no arguments" do
        @scanny.should parse('exec').without_issues
      end

      it "reports calls with one argument" do
        @scanny.should parse('exec "ls -l"').with_issue(:high,
          "The \"exec\" method can pass the executed command through shell exapnsion.")
      end

      it "does not report calls with multiple arguments" do
        @scanny.should parse('exec "ls", "-l"').without_issues
      end
    end
  end
end
