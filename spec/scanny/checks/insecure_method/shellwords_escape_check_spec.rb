module Scanny
  module Checks
    module InsecureMethod
      describe ShellwordsEscapeCheck do
        before do
          @runner = Scanny::Runner.new(ShellwordsEscapeCheck.new)
          @message =  "Execute escape method from Shellwords module" +
                      "can lead incomplete input filtering"

          @issue = issue(:high, @message, 184)
        end

        it "reports \"Shellwords.escape\" correctly" do
          @runner.should check("Shellwords.escape('shell-command')").with_issue(@issue)
        end

        it "reports \"shell_escape('command')\" correctly" do
          @runner.should check("shell_escape('command')").with_issue(@issue)
        end
      end
    end
  end
end