#!/usr/bin/env ruby
# Renders one report twice with the site's own Jekyll layouts, so the completeness
# and browser gates have a baseline for a report that is not published yet.
#
#   ruby render-report.rb <report folder holding index.md | path to index.md> <out dir> [baseline index.md] [--views FILE]
#
# Writes into <out dir>:
#   tagged.html     the report as written (tab lines kept)
#   untagged.html   the same markdown with every "{: .hl-tab-<token>}" line removed:
#                   the completeness baseline (check-report-text.js --baseline). With a third
#                   argument the baseline is rendered from THAT markdown instead (tab lines
#                   stripped), so words lost between an earlier copy (the vault's) and this
#                   one show as missing; the page is still this report's own
#   custom.css      assets/css/custom.scss compiled the way Jekyll does
#   render.json     { slug, folder, permalink, tab_lines, jekyll, kramdown, views }
#
# --views FILE  a report_views curation file (the content of _data/report_views/<folder>.yml) that lives
#               OUTSIDE this checkout, for example beside the vault report. It is rendered as
#               _data/report_views/<report folder>.yml in the scratch source, taking the place of a file of
#               that name in the checkout, so the page carries the curated views the live page will carry.
#               Without it the render uses only the curation files already in this checkout's _data.
#
# The report may live OUTSIDE this checkout (threat-intel-vault/reports/<slug>/).
# Nothing is written to this checkout: the site's _includes, _data and the two
# layouts are linked into a scratch source tree under <out dir>/src.
#
# GEMS NEEDED: jekyll (3.x), jekyll-seo-tag, kramdown-parser-gfm, sass (the Ruby
# Sass 3.7 gem; `gem install sass`), json. When one is missing this exits 2 with
# "NOT CHECKED" and the gem named: a gate that could not render has not passed.
#
# Exit 0 rendered, 1 the render failed, 2 NOT CHECKED (a gem is missing) or usage.

def not_checked(reason)
  puts "NOT CHECKED  render-report.rb: #{reason}"
  exit 2
end

begin
  require 'fileutils'
  require 'json'
  require 'yaml'
  require 'jekyll'
  require 'jekyll-seo-tag'
  require 'sass'
rescue LoadError => e
  not_checked("#{e.message}. Install the missing gem (gem install jekyll jekyll-seo-tag sass kramdown-parser-gfm), then re-run.")
end

views_file = nil
if (vi = ARGV.index('--views'))
  views_file = ARGV[vi + 1]
  if views_file.nil? || views_file.start_with?('--')
    warn '--views was given with no file after it'
    exit 2
  end
  ARGV.slice!(vi, 2)
end
if ARGV.length < 2 || ARGV.length > 3
  warn 'usage: ruby render-report.rb <report folder | path to index.md> <out dir> [baseline index.md] [--views FILE]'
  exit 2
end

repo = ENV['REPO'] || File.expand_path('../..', __dir__)
arg = File.expand_path(ARGV[0])
out = File.expand_path(ARGV[1])
file = File.directory?(arg) ? File.join(arg, 'index.md') : arg
unless File.file?(file)
  warn "no report markdown at #{file}"
  exit 2
end
baseline_file = ARGV[2] ? File.expand_path(ARGV[2]) : nil
baseline_file = File.join(baseline_file, 'index.md') if baseline_file && File.directory?(baseline_file)
if baseline_file && !File.file?(baseline_file)
  warn "no baseline markdown at #{baseline_file}"
  exit 2
end
folder = File.basename(File.dirname(file))
views_path = views_file ? File.expand_path(views_file) : nil
if views_path && !File.file?(views_path)
  warn "no report_views file at #{views_path}"
  exit 2
end
raw = File.read(file)
baseline_raw = baseline_file ? File.read(baseline_file) : raw
fm = raw[/\A---\r?\n(.*?)\r?\n---/m, 1]
permalink = fm && (YAML.safe_load(fm, permitted_classes: [Date, Time]) || {})['permalink']
slug = permalink ? permalink.to_s.sub(%r{\A/reports/}, '').sub(%r{/\z}, '') : folder

TAB_LINE = /^\{: \.hl-tab-[a-z]+\}\r?\n/
tab_lines = raw.scan(TAB_LINE).length

src = File.join(out, 'src')
FileUtils.rm_rf(src)
FileUtils.mkdir_p(File.join(src, '_layouts'))
FileUtils.ln_s(File.join(repo, '_includes'), File.join(src, '_includes'))
if views_path
  # _data is linked entry by entry so report_views can carry the one extra file; nothing in the checkout is written.
  FileUtils.mkdir_p(File.join(src, '_data', 'report_views'))
  Dir.children(File.join(repo, '_data')).each do |e|
    next if e == 'report_views'
    FileUtils.ln_s(File.join(repo, '_data', e), File.join(src, '_data', e))
  end
  rv = File.join(repo, '_data', 'report_views')
  Dir.children(rv).each do |e|
    next if e == "#{folder}.yml"
    FileUtils.ln_s(File.join(rv, e), File.join(src, '_data', 'report_views', e))
  end if File.directory?(rv)
  FileUtils.cp(views_path, File.join(src, '_data', 'report_views', "#{folder}.yml"))
else
  FileUtils.ln_s(File.join(repo, '_data'), File.join(src, '_data'))
end
%w[default.html post.html].each { |l| FileUtils.cp(File.join(repo, '_layouts', l), File.join(src, '_layouts', l)) }

config = Jekyll.configuration(
  'source' => src, 'destination' => File.join(out, 'gen'), 'config' => File.join(repo, '_config.yml'),
  'plugins' => ['jekyll-seo-tag'], 'remote_theme' => nil, 'quiet' => true,
  'github' => { 'build_revision' => 'render-report' },
  'markdown' => 'kramdown', 'kramdown' => { 'input' => 'GFM' }, 'exclude' => []
)

def render(config, src, folder, markdown)
  dir = File.join(src, 'reports', folder)
  FileUtils.rm_rf(File.join(src, 'reports'))
  FileUtils.mkdir_p(dir)
  File.write(File.join(dir, 'index.md'), markdown)
  site = Jekyll::Site.new(config)
  site.reset
  site.read
  page = site.pages.find { |p| p.path == "reports/#{folder}/index.md" }
  raise "Jekyll did not read reports/#{folder}/index.md" unless page
  Jekyll::Renderer.new(site, page).run
end

begin
  FileUtils.mkdir_p(out)
  File.write(File.join(out, 'tagged.html'), render(config, src, folder, raw))
  File.write(File.join(out, 'untagged.html'), render(config, src, folder, baseline_raw.gsub(TAB_LINE, '')))
  css = File.read(File.join(repo, 'assets/css/custom.scss')).sub(/\A---\n---\n/, '')
            .gsub(/\{%-?\s*comment\s*-?%\}.*?\{%-?\s*endcomment\s*-?%\}/m, '')
  File.write(File.join(out, 'custom.css'), Sass::Engine.new(css, syntax: :scss, style: :compressed).render)
  File.write(File.join(out, 'render.json'), JSON.pretty_generate(
    'slug' => slug, 'folder' => folder, 'permalink' => permalink, 'tab_lines' => tab_lines, 'baseline' => baseline_file,
    'jekyll' => Jekyll::VERSION, 'kramdown' => Kramdown::VERSION, 'views' => views_path
  ))
rescue StandardError => e
  puts "FAIL  render-report.rb: #{e.class}: #{e.message.lines.first}"
  exit 1
end
puts "rendered #{slug}: tagged.html, untagged.html (#{tab_lines} tab line(s) stripped), custom.css in #{out}#{views_path ? " (report_views from #{views_path})" : ''}"
