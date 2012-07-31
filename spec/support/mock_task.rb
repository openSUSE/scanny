module Scanny
  class MockTask
    class << self
      attr_accessor :last_instance, :last_cmd
    end

    def self.tasks
      @tasks ||= {}
    end

    def self.reset_tasks
      @tasks = {}
    end

    def self.task(name)
      tasks[name]
    end

    def self.register_task(name, block)
      tasks[name] = block
    end

    def initialize(name, &block)
      MockTask.register_task(name, block)
      MockTask.last_instance = block
    end

    def self.create_task(name, &block)
      new(name, &block)
    end
  end

  class RakeTask
    def task(name, &block)
      MockTask.create_task(name, &block)
    end

    def system(cmd)
      MockTask.last_cmd = cmd
      true
    end
  end
end