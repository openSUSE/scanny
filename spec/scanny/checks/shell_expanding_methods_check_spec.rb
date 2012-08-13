require "spec_helper"

module Scanny::Checks
  describe ShellExpandingMethodsCheck do
    before :each do
      @runner = Scanny::Runner.new(ShellExpandingMethodsCheck.new)

      @backtick_issue = issue(:high,
        "The \"`\" method passes the executed command through shell expansion.",
        [88, 78])
      @exec_issue = issue(:high,
        "The \"exec\" method passes the executed command through shell expansion.",
        [88, 78])
      @system_issue = issue(:high,
        "The \"system\" method passes the executed command through shell expansion.",
        [88, 78])
      @popen_issue = issue(:high,
        "The \"popen\" method passes the executed command through shell expansion.",
        [88, 78])
      @popen3_issue = issue(:high,
      "The \"popen3\" method passes the executed command through shell expansion.",
        [88, 78])
      @spawn_issue = issue(:high,
        "The \"spawn\" method passes the executed command through shell expansion.",
        [88, 78])
    end

    it "reports \"Kernel.`\" correctly" do
      @runner.should check('Kernel.` "ls -l"').with_issue(@backtick_issue)
      @runner.should check('Foo.` "ls -l"').without_issues
      @runner.should check('foo.` "ls -l"').without_issues
    end

    it "reports \"Kernel.exec\" correctly" do
      @runner.should check('exec "ls -l"').with_issue(@exec_issue)
      @runner.should check('Kernel.exec "ls -l"').with_issue(@exec_issue)
      @runner.should check('Foo.exec "ls -l"').without_issues
      @runner.should check('foo.exec "ls -l"').without_issues
    end

    it "reports \"Kernel.system\" correctly" do
      @runner.should check('system "ls -l"').with_issue(@system_issue)
      @runner.should check('Kernel.system "ls -l"').with_issue(@system_issue)
      @runner.should check('Foo.system "ls -l"').without_issues
      @runner.should check('foo.system "ls -l"').without_issues
    end

    it "reports calls with one argument only" do
      @runner.should check('exec').without_issues
      @runner.should check('exec "ls -l"').with_issue(@exec_issue)
      @runner.should check('exec "ls", "-l"').without_issues
    end

    it "reports \"popen\" correctly" do
      @runner.should check("IO.popen(arguments)").with_issue(@popen_issue)
      @runner.should check("IO.popen3(arguments)").with_issue(@popen3_issue)
    end

    it "reports \"spawn\" correctly" do
      @runner.should check("spawn('rm -rf /')").with_issue(@spawn_issue)
    end

    it "reports \"`ls`\" correctly" do
      @runner.should check("`ls`").with_issue(@backtick_issue)
    end
  end
end
