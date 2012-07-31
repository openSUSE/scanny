require 'rake'
require 'rake/tasklib'

module Scanny
  class RakeTask < ::Rake::TaskLib
    # name of rake task
    attr_accessor :name
    # paths to custom checks
    attr_accessor :include
    # list of disabled checks
    attr_accessor :disable
    # output format
    attr_accessor :format
    # strict mode
    attr_accessor :strict
    # custom path to scan
    attr_accessor :path
    # raise exception on error
    attr_accessor :fail_on_error

    def initialize(name=:scanny)
      @name           = name
      @include        = []
      @disable        = []
      @format         = nil
      @strict         = nil
      @path           = nil
      @fail_on_error  = nil

      yield self if block_given?
      define
    end

    def define
      desc("Run scanny security scanner")

      task name do
        cmd =   ["scanny"]
        cmd <<  ["-i"] + [@include] unless @include.empty?
        cmd <<  ["-d"] + [@disable] unless @disable.empty?
        cmd <<  ["-f #{@format}"]   if @format
        cmd <<  ["-s"]              if @strict
        cmd <<  [@path]             if @path
        cmd = cmd.flatten.join(" ")

        unless system(cmd)
          raise("Command #{cmd} failed") if fail_on_error
        end
      end
    end
  end
end