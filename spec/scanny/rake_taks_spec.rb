require 'spec_helper'

module Scanny
  describe RakeTask do
    before(:each) { MockTask.reset_tasks }

    it "executes clean scanny" do
      task = RakeTask.new
      MockTask.last_instance.call
      MockTask.last_cmd.should == "scanny"
    end

    it "executes scanny with format" do
      task = RakeTask.new { |t| t.format = :stdout }
      MockTask.last_instance.call
      MockTask.last_cmd.should == "scanny -f stdout"
    end

    it "executes scanny with include option" do
      task = RakeTask.new { |t| t.include = "./checks" }
      MockTask.last_instance.call
      MockTask.last_cmd.should == "scanny -i ./checks"
    end

    it "executes scanny with many include option" do
      task = RakeTask.new { |t| t.include = ["./checks", "./checks2"] }
      MockTask.last_instance.call
      MockTask.last_cmd.should == "scanny -i ./checks ./checks2"
    end

    it "executes scanny with disable options" do
      task = RakeTask.new { |t| t.disable = "HTTPRequestCheck" }
      MockTask.last_instance.call
      MockTask.last_cmd.should == "scanny -d HTTPRequestCheck"
    end

    it "executes scanny with many disable options" do
      task = RakeTask.new { |t| t.disable = ["HTTPRequestCheck", "Check"] }
      MockTask.last_instance.call
      MockTask.last_cmd.should == "scanny -d HTTPRequestCheck Check"
    end

    it "executes scanny in strict mode" do
      task = RakeTask.new { |t| t.strict = true }
      MockTask.last_instance.call
      MockTask.last_cmd.should == "scanny -s"
    end

    it "executes scanny with custom directory" do
      task = RakeTask.new { |t| t.path = "./custom/app" }
      MockTask.last_instance.call
      MockTask.last_cmd.should == "scanny ./custom/app"
    end

    describe "system command return false" do
      before do
        task = RakeTask.new { |t| t.fail_on_error = true }
        def task.system(*) return false end
      end

      it "fails on error" do
        lambda {
          MockTask.last_instance.call
        }.should raise_error(RuntimeError)
      end
    end
  end
end