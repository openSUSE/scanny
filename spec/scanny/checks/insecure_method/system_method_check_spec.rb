module Scanny
  module Checks
    module InsecureMethod
      describe SystemMethodCheck do
        before do
          @runner = Scanny::Runner.new(SystemMethodCheck.new)
          @message = "Execute system commands can lead the system to run dangerous code"

          @issue = issue(:high, @message, [88, 78])
        end

        it "reports \"popen\" correctly" do
          @runner.should check("IO.popen(arguments)").with_issue(@issue)
        end

        it "reports \"system\" correctly" do
          @runner.should check("system('rm -rf /')").with_issue(@issue)
        end

        it "reports \"spawn\" correctly" do
          @runner.should check("spawn('rm -rf /')").with_issue(@issue)
        end

        it "reports \"`ls`\" correctly" do
          @runner.should check("`ls`").with_issue(@issue)
        end
      end
    end
  end
end