require "spec_helper"

module Scanny::Checks::SystemTools
  describe TarCheck do
    before do
      @runner = Scanny::Runner.new(TarCheck.new)
      @message =  "Tar command can execute dangerous operations on files" +
                  "and can travel through directories"
      @issue = issue(:medium, @message, 88)
    end

    it "reports \"system('tar xvf archive.tar.gz')\" correctly" do
      @runner.should check("system('tar xvf archive.tar.gz')").with_issue(@issue)
    end

    it "reports \"`tar xvf archive.tar.gz`\" correctly" do
      @runner.should check("`tar xvf archive.tar.gz`").with_issue(@issue)
    end
  end
end
