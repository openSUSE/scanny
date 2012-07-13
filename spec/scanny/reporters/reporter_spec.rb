require "spec_helper"

module Scanny
  module Reporters
    describe Reporter do
      describe "initialize" do
        it "setup correctly instance variables" do
          arguments = {
            :file             => :file,
            :checks_performed => :checks_performed,
            :nodes_inspected  => :nodes_inspected,
            :issues           => :issues
          }
          reporter = Reporter.new(arguments)

          reporter.file.should be_equal(arguments[:file])
          reporter.checks_performed.should be_equal(arguments[:checks_performed])
          reporter.nodes_inspected.should be_equal(arguments[:nodes_inspected])
          reporter.issues.should be_equal(arguments[:issues])
        end
      end
    end
  end
end