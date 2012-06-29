require "spec_helper"

module Scanny::Checks::SystemTools
  describe TarCommandsCheck do
    before do
      @runner = Scanny::Runner.new(TarCommandsCheck.new)
      @message = "Tar command has an option that allows to run external programs"
      @issue = issue(:high, @message, 88)
    end

    it "reports \"system('tar xvf --to-command=exploit archive.tar')`\" correctly" do
      @runner.should  check("system('tar xvf --to-command=exploit archive.tar')").
                          with_issue(@issue)
    end

    it "reports \"`tar xvf --to-command=exploit archive.tar`\" correctly" do
      @runner.should  check("`tar xvf --to-command=exploit archive.tar`").
                      with_issue(@issue)
    end

    it "reports \"system('tar xvf --rmt-command=exploit archive.tar')`\" correctly" do
      @runner.should  check("system('tar xvf --rmt-command=exploit archive.tar')").
                          with_issue(@issue)
    end

    it "reports \"`tar xvf --rmt-command=exploit archive.tar`\" correctly" do
      @runner.should  check("`tar xvf --rmt-command=exploit archive.tar`").
                          with_issue(@issue)
    end

    it "reports \"system('tar xvf --rsh-command=exploit archive.tar')`\" correctly" do
      @runner.should  check("system('tar xvf --rsh-command=exploit archive.tar')").
                          with_issue(@issue)
    end

    it "reports \"`tar xvf --rsh-command=exploit archive.tar`\" correctly" do
      @runner.should  check("`tar xvf --rsh-command=exploit archive.tar`").
                          with_issue(@issue)
    end
  end
end
