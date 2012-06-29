require "spec_helper"

module Scanny::Checks::SystemTools
  describe SudoCheck do
    before do
      @runner = Scanny::Runner.new(SudoCheck.new)
      @message =  "Using sudo can lead to the execution" +
                  "of programs on root administrator rights"
      @issue = issue(:info, @message, 0)
    end

    it "reports \"system('sudo shutdown -h now')\" correctly" do
      @runner.should check("system('sudo shutdown -h now')").with_issue(@issue)
    end

    it "reports \"exec('sudo shutdown -h now')\" correctly" do
      @runner.should check("exec('sudo shutdown -h now')").with_issue(@issue)
    end

    it "reports \"`sudo shutdown -h now`\" correctly" do
      @runner.should check("`sudo shutdown -h now`").with_issue(@issue)
    end
  end
end
