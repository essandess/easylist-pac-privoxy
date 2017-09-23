#!/usr/bin/env python3
# -*- coding: utf-8 -*-
__author__ = 'stsmith'

# easylist_pac: Convert EasyList Tracker and Adblocking rules to an efficient Proxy Auto Configuration file

# Copyright (C) 2017 by Steven T. Smith <steve dot t dot smith at gmail dot com>, GPL

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse as ap, copy, datetime, functools as fnt, numpy as np, os, re, sys, time, urllib.request, warnings

try:
    machine_learning_flag = True
    import multiprocessing as mp, scipy.sparse as sps
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
except ImportError as e:
    machine_learning_flag = False
    print(e)
    warnings.warn("Install scikit-learn for more accurate EasyList rule selection.")

try:
    plot_flag = True
    import matplotlib as mpl, matplotlib.pyplot as plt
    # Legible plot style defaults
    # http://matplotlib.org/api/matplotlib_configuration_api.html
    # http://matplotlib.org/users/customizing.html
    mpl.rcParams['figure.figsize'] = (10.0, 5.0)
    mpl.rc('font', **{'family': 'sans-serif', 'weight': 'bold', 'size': 14})
    mpl.rc('axes', **{'titlesize': 20, 'titleweight': 'bold', 'labelsize': 16, 'labelweight': 'bold'})
    mpl.rc('legend', **{'fontsize': 14})
    mpl.rc('figure', **{'titlesize': 16, 'titleweight': 'bold'})
    mpl.rc('lines', **{'linewidth': 2.5, 'markersize': 18, 'markeredgewidth': 0})
    mpl.rc('mathtext',
           **{'fontset': 'custom', 'rm': 'sans:bold', 'bf': 'sans:bold', 'it': 'sans:italic', 'sf': 'sans:bold',
              'default': 'it'})
    # plt.rc('text',usetex=False) # [default] usetex should be False
    mpl.rcParams['text.latex.preamble'] = [r'\\usepackage{amsmath,sfmath} \\boldmath']
except ImportError as e:
    plot_flag = False
    print(e)
    warnings.warn("Install matplotlib to plot rule priorities.")

class EasyListPAC:
    '''Create a Proxy Auto Configuration file from EasyList rule sets.'''

    def __init__(self):
        self.parseArgs()
        self.easylists_download_latest()
        self.parse_and_filter_rule_files()
        self.prioritize_rules()
        if self.debug:
            print("Good rules and strengths:\n" + '\n'.join('{: 5d}:\t{}\t\t[{:2.1f}]'.format(i,r,s) for (i,(r,s)) in enumerate(zip(self.good_rules,self.good_signal))))
            print("\nBad rules and strengths:\n" + '\n'.join('{: 5d}:\t{}\t\t[{:2.1f}]'.format(i,r,s) for (i,(r,s)) in enumerate(zip(self.bad_rules,self.bad_signal))))
            if plot_flag:
                # plt.plot(np.arange(len(self.good_signal)), self.good_signal, '.')
                # plt.show()
                plt.plot(np.arange(len(self.bad_signal)), self.bad_signal, '.')
                plt.xlabel('Rule index')
                plt.ylabel('Bad rule distance (logit)')
                plt.show()
            return
        self.parse_easylist_rules()
        self.create_pac_file()

    def parseArgs(self):
        # blackhole specification in arguments
        # best choise is the LAN IP address of the http://hostname/proxy.pac web server, e.g. 192.168.0.2:80
        parser = ap.ArgumentParser()
        parser.add_argument('-b', '--blackhole', help="Blackhole IP:port", type=str, default='127.0.0.1:80')
        parser.add_argument('-d', '--download-dir', help="Download directory", type=str, default='~/Downloads')
        parser.add_argument('-g', '--debug', help="Debug: Just print rules", action='store_true')
        parser.add_argument('-p', '--proxy', help="Proxy host:port", type=str, default='')
        parser.add_argument('-P', '--PAC-original', help="Original proxy.pac file", type=str, default='proxy.pac.orig')
        parser.add_argument('-rb', '--bad-rule-max', help="Maximum number of bad rules (-1 for unlimited)", type=int,
                            default=9999)
        parser.add_argument('-rg', '--good-rule-max', help="Maximum number of good rules (-1 for unlimited)",
                            type=int, default=999)
        parser.add_argument('-th', '--truncate_hash', help="Truncate hash object length to maximum number", type=int,
                            default=3999)
        parser.add_argument('-tr', '--truncate_regex', help="Truncate regex rules to maximum number", type=int,
                            default=3999)
        parser.add_argument('-w', '--sliding-window', help="Sliding window training and test (slow)", action='store_true')
        parser.add_argument('-x', '--Extra_EasyList_URLs', help="Limit the number of wildcards", type=str, nargs='+', default=[])
        parser.add_argument('-*', '--wildcard-limit', help="Limit the number of wildcards", type=int, default=999)
        parser.add_argument('-@@', '--exceptions_include_flag', help="Include exception rules", action='store_true')
        args = parser.parse_args()
        self.args = parser.parse_args()
        self.blackhole_ip_port = args.blackhole
        self.easylist_dir = os.path.expanduser(args.download_dir)
        self.debug = args.debug
        self.proxy_host_port = args.proxy
        self.orig_pac_file = os.path.join(self.easylist_dir, args.PAC_original)
        # n.b. negative limits are set to no limits using [:None] slicing trick
        self.good_rule_max = args.good_rule_max if args.good_rule_max >= 0 else None
        self.bad_rule_max = args.bad_rule_max if args.bad_rule_max >= 0 else None
        self.truncate_hash_max = args.truncate_hash if args.truncate_hash >= 0 else None
        self.truncate_alternatives_max = args.truncate_regex if args.truncate_regex >= 0 else None
        self.sliding_window = args.sliding_window
        self.exceptions_include_flag = args.exceptions_include_flag
        self.wildcard_named_group_limit = args.wildcard_limit if args.wildcard_limit >= 0 else None
        self.extra_easylist_urls = args.Extra_EasyList_URLs
        return self.args

    def easylists_download_latest(self):
        easylist_url = 'https://easylist.to/easylist/easylist.txt'
        easyprivacy_url = 'https://easylist.to/easylist/easyprivacy.txt'
        fanboy_annoyance_url = 'https://easylist.to/easylist/fanboy-annoyance.txt'
        self.download_list = [fanboy_annoyance_url, easyprivacy_url, easylist_url] + self.extra_easylist_urls
        self.file_list = []
        for url in self.download_list:
            fname = os.path.basename(url)
            fname_full = os.path.join(self.easylist_dir, fname)
            file_utc = file_to_utc(fname_full) if os.path.isfile(os.path.join(self.easylist_dir, fname)) else 0.
            resp = urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': user_agent}))
            url_utc = last_modified_to_utc(last_modified_resp(resp))
            if (url_utc > file_utc) or (os.path.getsize(fname_full) == 0):  # download the newer file
                with open(fname_full, mode='w', encoding='utf-8') as out_file:
                    out_file.write(resp.read().decode('utf-8'))
            self.file_list.append(fname_full)

    def parse_and_filter_rule_files(self):
        """Parse all rules into good and bad lists. Use flags to specify included/excluded rules."""
        self.good_rules = []
        self.bad_rules = []
        self.good_opts = []
        self.bad_opts = []
        self.good_rules_include_flag = []
        self.bad_rules_include_flag = []
        for file in self.file_list:
            with open(file, 'r', encoding='utf-8') as fd:
                self.easylist_append_rules(fd)

    def easylist_append_rules(self, fd):
        """Append EasyList rules from file to good and bad lists."""
        ignore_rules_flag = False
        for line in fd:
            line = line.rstrip()
            line_orig = line
            # configuration lines and selector rules should already be filtered out
            if re_test(configuration_re, line) or re_test(selector_re, line): continue
            exception_flag = exception_filter(line)  # block default; pass if True
            line = exception_re.sub('\\1', line)
            option_exception_re = not3dimppuposgh_option_exception_re  # ignore these options by default
            # delete all easylist options **prior** to regex and selector cases
            # ignore domain limits for now
            opts = ''  # default: no options in the rule
            if re_test(option_re, line):
                opts = option_re.sub('\\2', line)
                # domain-specific and other option exceptions: ignore
                # too many rules (>~ 10k) bog down the browser; make reasonable exclusions here
                line = option_re.sub('\\1', line)  # delete all the options and continue
            # ignore these cases
            # comment case: ignore
            if re_test(comment_re, line):
                if re_test(commentname_sections_ignore_re, line):
                    ignored_rules_comment_start = comment_re.sub('', line)
                    if not ignore_rules_flag:
                        ignored_rules_count = 0
                        ignore_rules_flag = True
                        print('Ignore rules following comment ', end='', flush=True)
                    print('"{}"… '.format(ignored_rules_comment_start), end='', flush=True)
                else:
                    if ignore_rules_flag: print('\n {:d} rules ignored.'.format(ignored_rules_count), flush=True)
                    ignored_rules_count = 0
                    ignore_rules_flag = False
                continue
            if ignore_rules_flag:
                ignored_rules_count += 1
                self.append_rule(exception_flag, line, opts, False)
                continue
            # blank url case: ignore
            if re_test(httpempty_re, line): continue
            # blank line case: ignore
            if not bool(line): continue
            # block default or pass exception
            if exception_flag:
                option_exception_re = not3dimppuposgh_option_exception_re  # ignore these options within exceptions
                if not self.exceptions_include_flag:
                    self.append_rule(exception_flag, line, opts, False)
                    continue
            # specific options: ignore
            if re_test(option_exception_re, opts):
                self.append_rule(exception_flag, line, opts, False)
                continue
            # add all remaining rules
            self.append_rule(exception_flag, line, opts, True)

    def append_rule(self,exception_flag,rule, opts, include_rule_flag):
        if not bool(rule): return  # last chance to reject blank lines -- shouldn't happen
        if exception_flag:
            self.good_rules.append(rule)
            self.good_opts.append(option_tokenizer(opts))
            self.good_rules_include_flag.append(include_rule_flag)
        else:
            self.bad_rules.append(rule)
            self.bad_opts.append(option_tokenizer(opts))
            self.bad_rules_include_flag.append(include_rule_flag)

    def good_class_test(self,rule,opts=''):
        return not bool(badregex_regex_filters_re.search(rule))

    def bad_class_test(self,rule,opts=''):
        """Bad rule of interest if a match for the bad regex's or specific rule options,
e.g. non-domain specific popups or images."""
        return bool(badregex_regex_filters_re.search(rule)) \
                or (bool(opts) and bool(thrdp_im_pup_os_option_re.search(opts))
                    and not bool(not3dimppupos_option_exception_re.search(opts)))

    def prioritize_rules(self):
        # use bootstrap regex preferences
        # https://github.com/seatgeek/fuzzywuzzy would be great here if there were such a thing for regex
        self.good_signal = np.array([self.good_class_test(x,opts) for (x,opts,f) in zip(self.good_rules,self.good_opts,self.good_rules_include_flag) if f], dtype=np.int)
        self.bad_signal = np.array([self.bad_class_test(x,opts) for (x,opts,f) in zip(self.bad_rules,self.bad_opts,self.bad_rules_include_flag) if f], dtype=np.int)

        self.good_columns = np.array([i for (i,f) in enumerate(self.good_rules_include_flag) if f],dtype=int)
        self.bad_columns = np.array([i for (i,f) in enumerate(self.bad_rules_include_flag) if f],dtype=int)

        # Logistic Regression for more accurate rule priorities
        if machine_learning_flag:
            print("Performing logistic regression on rule sets. This will take a few minutes…",end='',flush=True)
            self.logreg_priorities()
            print(" done.", flush=True)

            # truncate to positive signal strengths
            if not self.debug:
                self.good_rule_max = min(self.good_rule_max,np.count_nonzero(self.good_signal > 0)) \
                    if isinstance(self.good_rule_max,(int,np.int)) else np.count_nonzero(self.good_signal > 0)
                self.bad_rule_max = min(self.bad_rule_max, np.count_nonzero(self.bad_signal > 0)) \
                    if isinstance(self.bad_rule_max,(int,np.int)) else np.count_nonzero(self.bad_signal > 0)

        # prioritize and limit the rules
        good_pridx = np.array([e[0] for e in sorted(enumerate(self.good_signal),key=lambda e: e[1],reverse=True)],dtype=int)[:self.good_rule_max]
        self.good_columns = self.good_columns[good_pridx]
        self.good_signal = self.good_signal[good_pridx]
        self.good_rules = [self.good_rules[k] for k in self.good_columns]
        bad_pridx = np.array([e[0] for e in sorted(enumerate(self.bad_signal),key=lambda e: e[1],reverse=True)],dtype=int)[:self.bad_rule_max]
        self.bad_columns = self.bad_columns[bad_pridx]
        self.bad_signal = self.bad_signal[bad_pridx]
        self.bad_rules = [self.bad_rules[k] for k in self.bad_columns]

        # include hardcoded rules
        for rule in include_these_good_rules:
            if rule not in self.good_rules: self.good_rules.append(rule)
        for rule in include_these_bad_rules:
            if rule not in self.bad_rules: self.bad_rules.append(rule)

        # rules are now ordered
        self.good_columns = np.arange(0,len(self.good_rules),dtype=self.good_columns.dtype)
        self.bad_columns = np.arange(0,len(self.bad_rules),dtype=self.bad_columns.dtype)

        return

    def logreg_priorities(self):
        """Rule prioritization using logistic regression on bootstrap preferences."""
        self.good_fv_json = {}
        self.good_column_hash = {}
        for col, (rule,opts) in enumerate(zip(self.good_rules,self.good_opts)):
            feature_vector_append_column(rule, opts, col, self.good_fv_json)
            self.good_column_hash[rule] = col
        self.bad_fv_json = {}
        self.bad_column_hash = {}
        for col, (rule,opts) in enumerate(zip(self.bad_rules,self.bad_opts)):
            feature_vector_append_column(rule, opts, col, self.bad_fv_json)
            self.bad_column_hash[rule] = col

        self.good_fv_mat, self.good_row_hash = fv_to_mat(self.good_fv_json, self.good_rules)
        self.bad_fv_mat, self.bad_row_hash = fv_to_mat(self.bad_fv_json, self.bad_rules)

        self.good_X_all = StandardScaler(with_mean=False).fit_transform(self.good_fv_mat.astype(np.float))
        self.good_y_all = np.array([self.good_class_test(x,opts) for (x,opts) in zip(self.good_rules, self.good_opts)], dtype=np.int)

        self.bad_X_all = StandardScaler(with_mean=False).fit_transform(self.bad_fv_mat.astype(np.float))
        self.bad_y_all = np.array([self.bad_class_test(x,opts) for (x,opts) in zip(self.bad_rules, self.bad_opts)], dtype=np.int)

        self.logit_fit_method_sample_weights()

        # inverse regularization signal; smaller values give more sparseness, less model rigidity
        self.C = 1.e1

        self.logreg_test_in_training()
        if self.sliding_window: self.logreg_sliding_window()

        return

    def debug_feature_vector(self,rule_substring=r'google.com/pagead'):
        for j, rule in enumerate(self.bad_rules):
            if rule.find(rule_substring) >= 0: break
        col = j
        print(self.bad_rules[col])
        _, rows = self.bad_fv_mat[col,:].nonzero()  # fv_mat is transposed
        print(rows)
        for row in rows:
            print('Row {:d}: {}:: {:g}'.format(row, self.bad_row_hash[int(row)], self.bad_fv_mat[col, row]))

    def logit_fit_method_sample_weights(self):
        # weights for LogisticRegression.fit()
        self.good_w_all = np.ones(len(self.good_y_all))
        self.bad_w_all = np.ones(len(self.bad_y_all))

        # add more weight for each of these regex matches
        for i, rule in enumerate(self.bad_rules):
            self.bad_w_all[i] += 1/max(1,len(rule))  # slight disadvantage for longer rules
            for regex in high_weight_regex:
                self.bad_w_all[i] += len(regex.findall(rule))
            # these options have more weight
            self.bad_w_all[i] += bool(thrdp_im_pup_os_option_re.search(self.bad_opts[i]))
        return

    def logreg_test_in_training(self):
        """fast, initial method: test vectors in the training data"""

        self.good_fv_logreg = LogisticRegression(C=self.C, penalty='l2', solver='liblinear', tol=0.01)
        self.bad_fv_logreg = LogisticRegression(C=self.C, penalty='l2', solver='liblinear', tol=0.01)

        good_x_test = self.good_X_all[self.good_columns]
        good_X = self.good_X_all
        good_y = self.good_y_all
        good_w = self.good_w_all

        bad_x_test = self.bad_X_all[self.bad_columns]
        bad_X = self.bad_X_all
        bad_y = self.bad_y_all
        bad_w = self.bad_w_all

        if good_x_test.shape[0] > 0:
            self.good_fv_logreg.fit(good_X, good_y, sample_weight=good_w)
            self.good_signal = self.good_fv_logreg.decision_function(good_x_test)
        if bad_x_test.shape[0] > 0:
            self.bad_fv_logreg.fit(bad_X, bad_y, sample_weight=bad_w)
            self.bad_signal = self.bad_fv_logreg.decision_function(bad_x_test)
        return

    def logreg_sliding_window(self):
        """bootstrap the signal strengths by removing test vectors from training"""

        # pre-prioritize using test-in-target values and limit the rules
        if not self.debug:
            good_preidx = np.array([e[0] for e in sorted(enumerate(self.good_signal),key=lambda e: e[1],reverse=True)],dtype=int)[:int(np.ceil(1.4*self.good_rule_max))]
            self.good_columns = self.good_columns[good_preidx]
            bad_preidx = np.array([e[0] for e in sorted(enumerate(self.bad_signal),key=lambda e: e[1],reverse=True)],dtype=int)[:int(np.ceil(1.4*self.bad_rule_max))]
            self.bad_columns = self.bad_columns[bad_preidx]

        # multithreaded loop for speed
        use_blocked_not_sklearn_mp = True  # it's a lot faster to block it yourself
        if use_blocked_not_sklearn_mp:
            # init w/ target-in-training results
            good_fv_logreg = copy.deepcopy(self.good_fv_logreg)
            good_fv_logreg.penalty = 'l2'
            good_fv_logreg.solver = 'sag'
            good_fv_logreg.warm_start = True
            good_fv_logreg.n_jobs = 1  # achieve parallelism via block processing
            bad_fv_logreg = copy.deepcopy(self.bad_fv_logreg)
            bad_fv_logreg.penalty = 'l2'
            bad_fv_logreg.solver = 'sag'
            bad_fv_logreg.warm_start = True
            bad_fv_logreg.n_jobs = 1  # achieve parallelism via block processing
            if False:  # debug mp: turn off multiprocessing with a monkeypatch
                class NotAMultiProcess(mp.Process):
                    def start(self): self.run()
                    def join(self): pass
                mp.Process = NotAMultiProcess

            # this is probably efficient with Linux's copy-on-write fork(); unsure about BSD/macOS
            # must refactor to use shared Array() [along with warm_start coeff's] to ensure
            # see https://stackoverflow.com/questions/5549190/is-shared-readonly-data-copied-to-different-processes-for-python-multiprocessing/

            # distribute training and tests across multiprocessors
            def training_op(queue, X_all, y_all, w_all, fv_logreg, columns, column_block):
                """Training and test operation put into a mp.Queue.
                columns[column_block] and signal[column_block] are the rule columns and corresponding signal strengths
                """
                res = np.zeros(len(column_block))
                for k in range(len(column_block)):
                    mask = np.zeros(len(y_all), dtype=bool)
                    mask[columns[column_block[k]]] = True
                    mask = np.logical_not(mask)

                    x_test = X_all[np.logical_not(mask)]
                    X = X_all[mask]
                    y = y_all[mask]
                    w = w_all[mask]

                    fv_logreg.fit(X, y, sample_weight=w)
                    res[k] = fv_logreg.decision_function(x_test)[0]
                queue.put((column_block,res))  # signal[column_block] = res
                return

            num_threads = mp.cpu_count()

            # good
            q = mp.Queue()
            jobs = []
            self.good_signal = np.zeros(len(self.good_columns))
            block_length = len(self.good_columns) // num_threads
            column_block = np.arange(0, block_length)
            while len(column_block) > 0:
                column_block = column_block[np.where(column_block < len(self.good_columns))]
                fv_logreg = copy.deepcopy(good_fv_logreg)  # each process gets its own .coeff_'s
                column_block_copy = np.copy(column_block)  # each process gets its own block of columns
                p = mp.Process(target=training_op, args=(q, self.good_X_all, self.good_y_all, self.good_w_all, fv_logreg, self.good_columns, column_block_copy))
                p.start()
                jobs.append(p)
                column_block += len(column_block)
            # process the results in the queue
            for i in range(len(jobs)):
                column_block, res = q.get()
                self.good_signal[column_block] = res
            # join all jobs and wait for them to complete
            for p in jobs: p.join()

            # bad
            q = mp.Queue()
            jobs = []
            self.bad_signal = np.zeros(len(self.bad_columns))
            block_length = len(self.bad_columns) // num_threads
            column_block = np.arange(0, block_length)
            while len(column_block) > 0:
                column_block = column_block[np.where(column_block < len(self.bad_columns))]
                fv_logreg = copy.deepcopy(bad_fv_logreg)   # each process gets its own .coeff_'s
                column_block_copy = np.copy(column_block)  # each process gets its own block of columns
                p = mp.Process(target=training_op, args=(q, self.bad_X_all, self.bad_y_all, self.bad_w_all, fv_logreg, self.bad_columns, column_block_copy))
                p.start()
                jobs.append(p)
                column_block += len(column_block)
            # process the results in the queue
            for i in range(len(jobs)):
                column_block, res = q.get()
                self.bad_signal[column_block] = res
            # join all jobs and wait for them to complete
            for p in jobs: p.join()
        else:  # if use_blocked_not_sklearn_mp:
            def training_op(X_all, y_all, w_all, fv_logreg, columns, signal):
                """Training and test operations reusing results with multiprocessing."""
                res = np.zeros(len(signal))
                for k in range(len(res)):
                    mask = np.zeros(len(y_all), dtype=bool)
                    mask[columns[k]] = True
                    mask = np.logical_not(mask)

                    x_test = X_all[np.logical_not(mask)]
                    X = X_all[mask]
                    y = y_all[mask]
                    w = w_all[mask]

                    fv_logreg.fit(X, y, sample_weight=w)
                    res[k] = fv_logreg.decision_function(x_test)[0]
                signal[:] = res
                return
            # good
            training_op(self.good_X_all, self.good_y_all, self.good_w_all, self.good_fv_logreg, self.good_columns, self.good_signal)
            # bad
            training_op(self.bad_X_all, self.bad_y_all, self.bad_w_all, self.bad_fv_logreg, self.bad_columns, self.bad_signal)
        return

    def parse_easylist_rules(self):
        for rule in self.good_rules: self.easylist_to_javascript_vars(rule)
        for rule in self.bad_rules: self.easylist_to_javascript_vars(rule)
        ordered_unique_all_js_var_lists()
        return

    def easylist_to_javascript_vars(self,rule,ignore_huge_url_regex_rule_list=False):
        rule = rule.rstrip()
        rule_orig = rule
        exception_flag = exception_filter(rule)  # block default; pass if True
        rule = exception_re.sub('\\1', rule)
        option_exception_re = not3dimppuposgh_option_exception_re  # ignore these options by default
        opts = ''  # default: no options in the rule
        if re_test(option_re, rule):
            opts = option_re.sub('\\2', rule)
            # domain-specific and other option exceptions: ignore
            # too many rules (>~ 10k) bog down the browser; make reasonable exclusions here
            rule = option_re.sub('\\1', rule)  # delete all the options and continue
        # ignore these cases
        # comment case: ignore
        if re_test(comment_re, rule): return
        # block default or pass exception
        if exception_flag:
            option_exception_re = not3dimppuposgh_option_exception_re  # ignore these options within exceptions
            if not self.exceptions_include_flag: return
        # specific options: ignore
        if re_test(option_exception_re, opts): return
        # blank url case: ignore
        if re_test(httpempty_re, rule): return
        # blank line case: ignore
        if not rule: return
        # treat each of the these cases separately, here and in Javascript
        # regex case
        if re_test(regex_re, rule):
            if regex_ignore_test(rule): return
            rule = regex_re.sub('\\1', rule)
            if exception_flag:
                good_url_regex.append(rule)
            else:
                if not re_test(badregex_regex_filters_re,
                               rule): return  # limit bad regex's to those in the filter
                bad_url_regex.append(rule)
            return
        # now that regex's are handled, delete unnecessary wildcards, e.g. /.../*
        rule = wildcard_begend_re.sub('\\1', rule)
        # domain anchors, || or '|http://a.b' -> domain anchor 'a.b' for regex efficiency in JS
        if re_test(domain_anch_re, rule) or re_test(scheme_anchor_re, rule):
            # strip off initial || or |scheme://
            if re_test(domain_anch_re, rule):
                rule = domain_anch_re.sub('\\1', rule)
            elif re_test(scheme_anchor_re, rule):
                rule = scheme_anchor_re.sub("", rule)
            # host subcase
            if re_test(da_hostonly_re, rule):
                rule = da_hostonly_re.sub('\\1', rule)
                if not re_test(wild_anch_sep_exc_re, rule):  # exact subsubcase
                    if not re_test(badregex_regex_filters_re, rule):
                        return  # limit bad regex's to those in the filter
                    if exception_flag:
                        good_da_host_exact.append(rule)
                    else:
                        bad_da_host_exact.append(rule)
                    return
                else:  # regex subsubcase
                    if regex_ignore_test(rule): return
                    if exception_flag:
                        good_da_host_regex.append(rule)
                    else:
                        if not re_test(badregex_regex_filters_re,
                                       rule): return  # limit bad regex's to those in the filter
                        bad_da_host_regex.append(rule)
                    return
            # hostpath subcase
            if re_test(da_hostpath_re, rule):
                rule = da_hostpath_re.sub('\\1', rule)
                if not re_test(wild_sep_exc_noanch_re, rule) and re_test(pathend_re, rule):  # exact subsubcase
                    rule = re.sub(r'\|$', '', rule)  # strip EOL anchors
                    if not re_test(badregex_regex_filters_re, rule):
                        return  # limit bad regex's to those in the filter
                    if exception_flag:
                        good_da_hostpath_exact.append(rule)
                    else:
                        bad_da_hostpath_exact.append(rule)
                    return
                else:  # regex subsubcase
                    if regex_ignore_test(rule): return
                    # ignore option rules for some regex rules
                    if re_test(alloption_exception_re, opts): return
                    if exception_flag:
                        good_da_hostpath_regex.append(rule)
                    else:
                        if not re_test(badregex_regex_filters_re,
                                       rule): return  # limit bad regex's to those in the filter
                        bad_da_hostpath_regex.append(rule)
                    return
            # hostpathquery default case
            if True:
                # if re_test(re.compile(r'^go\.'),rule):
                #     pass
                if regex_ignore_test(rule): return
                if exception_flag:
                    good_da_regex.append(rule)
                else:
                    bad_da_regex.append(rule)
                return
        # all other non-regex patterns
        if True:
            if regex_ignore_test(rule): return
            if not ignore_huge_url_regex_rule_list:
                if re_test(alloption_exception_re, opts): return
                if exception_flag:
                    good_url_parts.append(rule)
                else:
                    if not re_test(badregex_regex_filters_re,
                                   rule): return  # limit bad regex's to those in the filter
                    bad_url_parts.append(rule)
                return  # superfluous return

    def create_pac_file(self):
        self.proxy_pac_init()
        self.proxy_pac = self.proxy_pac_preamble \
                    + "\n".join(["// " + l for l in self.easylist_strategy.split("\n")]) \
                    + self.js_init_object('good_da_host_exact') \
                    + self.js_init_regexp('good_da_host_regex', True) \
                    + self.js_init_object('good_da_hostpath_exact') \
                    + self.js_init_regexp('good_da_hostpath_regex', True) \
                    + self.js_init_regexp('good_da_regex', True) \
                    + self.js_init_object('good_da_host_exceptions_exact') \
                    + self.js_init_object('bad_da_host_exact') \
                    + self.js_init_regexp('bad_da_host_regex', True) \
                    + self.js_init_object('bad_da_hostpath_exact') \
                    + self.js_init_regexp('bad_da_hostpath_regex', True) \
                    + self.js_init_regexp('bad_da_regex', True) \
                    + self.js_init_regexp('good_url_parts') \
                    + self.js_init_regexp('bad_url_parts') \
                    + self.js_init_regexp('good_url_regex') \
                    + self.js_init_regexp('bad_url_regex') \
                    + self.proxy_pac_postamble

        for l in ['good_da_host_exact',
                  'good_da_host_regex',
                  'good_da_hostpath_exact',
                  'good_da_hostpath_regex',
                  'good_da_regex',
                  'good_da_host_exceptions_exact',
                  'bad_da_host_exact',
                  'bad_da_host_regex',
                  'bad_da_hostpath_exact',
                  'bad_da_hostpath_regex',
                  'bad_da_regex',
                  'good_url_parts',
                  'bad_url_parts',
                  'good_url_regex',
                  'bad_url_regex']:
            print("{}: {:d} rules".format(l, len(globals()[l])), flush=True)

        with open(os.path.join(self.easylist_dir, 'proxy.pac'), 'w', encoding='utf-8') as fd:
            fd.write(self.proxy_pac)

    def proxy_pac_init(self):
        self.pac_proxy = 'PROXY {}'.format(self.proxy_host_port) if self.proxy_host_port else 'DIRECT'

        # define a default, user-supplied FindProxyForURL function
        self.default_FindProxyForURL_function = '''\
function FindProxyForURL(url, host)
{{
if (
   isPlainHostName(host) ||
   shExpMatch(host, "10.*") ||
   shExpMatch(host, "172.16.*") ||
   shExpMatch(host, "192.168.*") ||
   shExpMatch(host, "127.*") ||
   dnsDomainIs(host, ".LOCAL") ||
   dnsDomainIs(host, ".local") ||
   (url.substring(0,3) == "ftp")
)
        return "DIRECT";
else
        return "{}";
}}
'''.format(self.pac_proxy)

        if os.path.isfile(self.orig_pac_file):
            with open(self.orig_pac_file, 'r', encoding='utf-8') as fd:
                self.original_FindProxyForURL_function = fd.read()
        else:
            self.original_FindProxyForURL_function = self.default_FindProxyForURL_function

        # change the function name to MyFindProxyForURL
        self.original_FindProxyForURL_function = re.sub(r'function[\s]+FindProxyForURL', 'function MyFindProxyForURL',
                                               self.original_FindProxyForURL_function)

        #  proxy.pac preamble
        self.calling_command = ' '.join([os.path.basename(sys.argv[0])] + sys.argv[1:])
        self.proxy_pac_preamble = '''\
// PAC (Proxy Auto Configuration) Filter from EasyList rules
// 
// Copyright (C) 2017 by Steven T. Smith <steve dot t dot smith at gmail dot com>, GPL
// https://github.com/essandess/easylist-pac-privoxy/
//
// PAC file created on {}
// Created with command: {}
//
// http://www.gnu.org/licenses/lgpl.txt
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// If you normally use a proxy, replace "DIRECT" below with
// "PROXY MACHINE:PORT"
// where MACHINE is the IP address or host name of your proxy
// server and PORT is the port number of your proxy server.
//
// Influenced in part by code from King of the PAC from http://securemecca.com/pac.html

// Define the blackhole proxy for blocked adware and trackware

var normal = "DIRECT";
// var blackhole_ip_port = "127.0.0.1:80";  // test code
// var blackhole_ip_port = "8.8.8.8:53";    // GOOG DNS blackhole; do not use: causes long waits on some sites
var blackhole_ip_port = "{}";    // deployment code; use the same server as proxy.pac if possible
var blackhole = "PROXY " + blackhole_ip_port;

// The hostnames must be consistent with EasyList format.
// These special RegExp characters will be escaped below: [.?+@]
// This EasyList wildcard will be transformed to an efficient RegExp: *
// 
// EasyList format references:
// https://adblockplus.org/filters
// https://adblockplus.org/filter-cheatsheet

// Create object hashes or compile efficient NFA's from all filters
// Various alternate filtering and regex approaches were timed using node and at jsperf.com

// Too many rules (>~ 10k) bog down the browser; make reasonable exclusions here:

'''.format(time.strftime("%a, %d %b %Y %X GMT", time.gmtime()),self.calling_command,self.blackhole_ip_port)

        self.proxy_pac_postamble = '''
// Add any good networks here. Format is network folowed by a comma and
// optional white space, and then the netmask.
// LAN, loopback, Apple (direct and Akamai e.g. e4805.a.akamaiedge.net), Microsoft (updates and services)
var GoodNetworks_Array = [ "10.0.0.0,     255.0.0.0",
"172.16.0.0,        255.240.0.0",
"192.168.0.0,       255.255.0.0",
"127.0.0.0,         255.0.0.0",
"17.0.0.0,          255.0.0.0",
"23.2.8.68,         255.255.255.255",
"23.2.145.78,       255.255.255.255",
"23.39.179.17,      255.255.255.255",
"23.63.98.0,        255.255.254.0",
"104.70.71.223,     255.255.255.255",
"104.73.77.224,     255.255.255.255",
"104.96.184.235,    255.255.255.255",
"104.96.188.194,    255.255.255.255",
"65.52.0.0,         255.255.252.0" ];

// Apple iAd, Microsoft telemetry
var GoodNetworks_Exceptions_Array = [ "17.172.28.11,     255.255.255.255",
"134.170.30.202,    255.255.255.255",
"137.116.81.24,     255.255.255.255",
"157.56.106.189,    255.255.255.255",
"184.86.53.99,      255.255.255.255",
"2.22.61.43,        255.255.255.255",
"2.22.61.66,        255.255.255.255",
"204.79.197.200,    255.255.255.255",
"23.218.212.69,     255.255.255.255",
"65.39.117.230,     255.255.255.255",
"65.52.108.33,      255.255.255.255",
"65.55.108.23,      255.255.255.255",
"64.4.54.254,       255.255.255.255" ];

// Akamai: 23.64.0.0/14, 23.0.0.0/12, 23.32.0.0/11, 104.64.0.0/10

// Add any bad networks here. Format is network folowed by a comma and
// optional white space, and then the netmask.
// From securemecca.com: Adobe marketing cloud, 2o7, omtrdc, Sedo domain parking, flyingcroc, accretive
var BadNetworks_Array = [ "61.139.105.128,    255.255.255.192",
"63.140.35.160,  255.255.255.248",
"63.140.35.168,  255.255.255.252",
"63.140.35.172,  255.255.255.254",
"63.140.35.174,  255.255.255.255",
"66.150.161.32,  255.255.255.224",
"66.235.138.0,   255.255.254.0",
"66.235.141.0,   255.255.255.0",
"66.235.143.48,  255.255.255.254",
"66.235.143.64,  255.255.255.254",
"66.235.153.16,  255.255.255.240",
"66.235.153.32,  255.255.255.248",
"81.31.38.0,     255.255.255.128",
"82.98.86.0,     255.255.255.0",
"89.185.224.0,   255.255.224.0",
"207.66.128.0,   255.255.128.0" ];

// block these schemes; use the command line for ftp, rsync, etc. instead
var bad_schemes_RegExp = RegExp("^(?:ftp|sftp|tftp|ftp-data|rsync|finger|gopher)", "i")

// RegExp for schemes; lengths from
// perl -lane 'BEGIN{$l=0;} {!/^#/ && do{$ll=length($F[0]); if($ll>$l){$l=$ll;}};} END{print $l;}' /etc/services
var schemepart_RegExp = RegExp("^([\\\\w*+-]{2,15}):\\\\/{0,2}","i");
var hostpart_RegExp = RegExp("^((?:[\\\\w-]+\\\\.)+[a-zA-Z0-9-]{2,24}\\\\.?)", "i");
var querypart_RegExp = RegExp("^((?:[\\\\w-]+\\\\.)+[a-zA-Z0-9-]{2,24}\\\\.?[\\\\w~%.\\\\/^*-]+)(\\\\??[\\\\S]*?)$", "i");
var domainpart_RegExp = RegExp("^(?:[\\\\w-]+\\\\.)*((?:[\\\\w-]+\\\\.)[a-zA-Z0-9-]{2,24}\\\\.?)", "i");

//////////////////////////////////////////////////
// Define the is_ipv4_address function and vars //
//////////////////////////////////////////////////

var ipv4_RegExp = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function is_ipv4_address(host)
{
    var ipv4_pentary = host.match(ipv4_RegExp);
    var is_valid_ipv4 = false;

    if (ipv4_pentary) {
        is_valid_ipv4 = true;
        for( i = 1; i <= 4; i++) {
            if (ipv4_pentary[i] >= 256) {
                is_valid_ipv4 = false;
            }
        }
    }
    return is_valid_ipv4;
}

// object hashes
// Note: original stackoverflow-based hasOwnProperty does not woth within iOS kernel 
var hasOwnProperty = function(obj, prop) {
    return obj.hasOwnProperty(prop);
}

/////////////////////
// Done Setting Up //
/////////////////////

// debug with Chrome at chrome://net-internals/#events
// alert("Debugging message.")

//////////////////////////////////
// Define the FindProxyFunction //
//////////////////////////////////

var use_pass_rules_parts_flag = true;  // use the pass rules for url parts, then apply the block rules
var alert_flag = false;                // use for short-circuit '&&' to print debugging statements
var debug_flag = false;               // use for short-circuit '&&' to print debugging statements

function FindProxyForURL(url, host)
{
    var host_is_ipv4 = is_ipv4_address(host);
    var host_ipv4_address;

    alert_flag && alert("url is: " + url);
    alert_flag && alert("host is: " + host);

    // Extract scheme and url without scheme
    var scheme = url.match(schemepart_RegExp)
    scheme = scheme.length > 0? scheme[1] : "";

    // Remove the scheme and extract the path for regex efficiency
    var url_noscheme = url.replace(schemepart_RegExp,"");
    var url_pathonly = url_noscheme.replace(hostpart_RegExp,"");
    var url_noquery = url_noscheme.replace(querypart_RegExp,"$1");
    // Remove the server name from the url and host if host is not an IPv4 address
    var url_noserver = !host_is_ipv4 ? url_noscheme.replace(domainpart_RegExp,"$1") : url_noscheme;
    var url_noservernoquery = !host_is_ipv4 ? url_noquery.replace(domainpart_RegExp,"$1") : url_noscheme;
    var host_noserver =  !host_is_ipv4 ? host.replace(domainpart_RegExp,"$1") : host;

    // Debugging results
    if (debug_flag && alert_flag) {
        alert("url_noscheme is: " + url_noscheme);
        alert("url_pathonly is: " + url_pathonly);
        alert("url_noquery is: " + url_noquery);
        alert("url_noserver is: " + url_noserver);
        alert("url_noservernoquery is: " + url_noservernoquery);
        alert("host_noserver is: " + host_noserver);
    }

    // Short circuit to blackhole for good_da_host_exceptions
    if ( hasOwnProperty(good_da_host_exceptions_JSON,host) ) {
        alert_flag && alert("good_da_host_exceptions_JSON blackhole!");
        // Redefine url and host to avoid leaking information to the blackhole
        url = "http://127.0.0.1:80";
        host = "127.0.0.1";
        return blackhole;
    }

    ///////////////////////////////////////////////////////////////////////
    // Check to make sure we can get an IPv4 address from the given host //
    // name.  If we cannot do that then skip the Networks tests.         //
    ///////////////////////////////////////////////////////////////////////

    host_ipv4_address = host_is_ipv4 ? host : (isResolvable(host) ? dnsResolve(host) : false);

    if (host_ipv4_address) {
        alert_flag && alert("host ipv4 address is: " + host_ipv4_address);
        /////////////////////////////////////////////////////////////////////////////
        // If the IP translates to one of the GoodNetworks_Array (with exceptions) //
        // we pass it because it is considered safe.                               //
        /////////////////////////////////////////////////////////////////////////////

        for (i in GoodNetworks_Exceptions_Array) {
            tmpNet = GoodNetworks_Exceptions_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("GoodNetworks_Exceptions_Array Blackhole: " + host_ipv4_address);
                // Redefine url and host to avoid leaking information to the blackhole
                url = "http://127.0.0.1:80";
                host = "127.0.0.1";
                return blackhole;
            }
        }
        for (i in GoodNetworks_Array) {
            tmpNet = GoodNetworks_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("GoodNetworks_Array PASS: " + host_ipv4_address);
                return MyFindProxyForURL(url, host);
            }
        }

        ///////////////////////////////////////////////////////////////////////
        // If the IP translates to one of the BadNetworks_Array we fail it   //
        // because it is not considered safe.                                //
        ///////////////////////////////////////////////////////////////////////

        for (i in BadNetworks_Array) {
            tmpNet = BadNetworks_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("BadNetworks_Array Blackhole: " + host_ipv4_address);
                // Redefine url and host to avoid leaking information to the blackhole
                url = "http://127.0.0.1:80";
                host = "127.0.0.1";
                return blackhole;
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////////
    // HTTPS: https scheme can only use domain information                      //
    // unless PacHttpsUrlStrippingEnabled == false [Chrome] or                  //
    // network.proxy.autoconfig_url.include_path == true [firefox]              //
    // E.g. on macOS:                                                           //
    // defaults write com.google.Chrome PacHttpsUrlStrippingEnabled -bool false //
    // Check setting at page chrome://policy                                    //
    //////////////////////////////////////////////////////////////////////////////

    // Assume browser has disabled path access if scheme is https and path is '/'
    if ( scheme == "https" && url_pathonly == "/" ) {

        ///////////////////////////////////////////////////////////////////////
        // PASS LIST:   domains matched here will always be allowed.         //
        ///////////////////////////////////////////////////////////////////////

        if ( (good_da_host_exact_flag && (hasOwnProperty(good_da_host_JSON,host_noserver)||hasOwnProperty(good_da_host_JSON,host)))
            && !hasOwnProperty(good_da_host_exceptions_JSON,host) ) {
                alert_flag && alert("HTTPS PASS: " + host + ", " + host_noserver);
            return MyFindProxyForURL(url, host);
        }

        //////////////////////////////////////////////////////////
        // BLOCK LIST:	stuff matched here here will be blocked //
        //////////////////////////////////////////////////////////

        if ( (bad_da_host_exact_flag && (hasOwnProperty(bad_da_host_JSON,host_noserver)||hasOwnProperty(bad_da_host_JSON,host))) ) {
            alert_flag && alert("HTTPS blackhole: " + host + ", " + host_noserver);
            // Redefine url and host to avoid leaking information to the blackhole
            url = "http://127.0.0.1:80";
            host = "127.0.0.1";
            return blackhole;
        }
    }

    ////////////////////////////////////////
    // HTTPS and HTTP: full path analysis //
    ////////////////////////////////////////

    if (scheme == "https" || scheme == "http") {

        ///////////////////////////////////////////////////////////////////////
        // PASS LIST:   domains matched here will always be allowed.         //
        ///////////////////////////////////////////////////////////////////////

        if ( !hasOwnProperty(good_da_host_exceptions_JSON,host)
            && ((good_da_host_exact_flag && (hasOwnProperty(good_da_host_JSON,host_noserver)||hasOwnProperty(good_da_host_JSON,host))) ||  // fastest test first
                (use_pass_rules_parts_flag &&
                    (good_da_hostpath_exact_flag && (hasOwnProperty(good_da_hostpath_JSON,url_noservernoquery)||hasOwnProperty(good_da_hostpath_JSON,url_noquery)) ) ||
                    // test logic: only do the slower test if the host has a (non)suspect fqdn
                    (good_da_host_regex_flag && (good_da_host_RegExp.test(host_noserver)||good_da_host_RegExp.test(host))) ||
                    (good_da_hostpath_regex_flag && (good_da_hostpath_RegExp.test(url_noservernoquery)||good_da_hostpath_RegExp.test(url_noquery))) ||
                    (good_da_regex_flag && (good_da_RegExp.test(url_noserver)||good_da_RegExp.test(url_noscheme))) ||
                    (good_url_parts_flag && good_url_parts_RegExp.test(url)) ||
                    (good_url_regex_flag && good_url_regex_RegExp.test(url)))) ) {
            return MyFindProxyForURL(url, host);
        }

        //////////////////////////////////////////////////////////
        // BLOCK LIST:	stuff matched here here will be blocked //
        //////////////////////////////////////////////////////////
        // Debugging results
        if (debug_flag && alert_flag) {
            alert("hasOwnProperty(bad_da_host_JSON," + host_noserver + "): " + (bad_da_host_exact_flag && hasOwnProperty(bad_da_host_JSON,host_noserver)));
            alert("hasOwnProperty(bad_da_host_JSON," + host + "): " + (bad_da_host_exact_flag && hasOwnProperty(bad_da_host_JSON,host)));
            alert("hasOwnProperty(bad_da_hostpath_JSON," + url_noservernoquery + "): " + (bad_da_hostpath_exact_flag && hasOwnProperty(bad_da_hostpath_JSON,url_noservernoquery)));
            alert("hasOwnProperty(bad_da_hostpath_JSON," + url_noquery + "): " + (bad_da_hostpath_exact_flag && hasOwnProperty(bad_da_hostpath_JSON,url_noquery)));
            alert("bad_da_host_RegExp.test(" + host_noserver + "): " + (bad_da_host_regex_flag && bad_da_host_RegExp.test(host_noserver)));
            alert("bad_da_host_RegExp.test(" + host + "): " + (bad_da_host_regex_flag && bad_da_host_RegExp.test(host)));
            alert("bad_da_hostpath_RegExp.test(" + url_noservernoquery + "): " + (bad_da_hostpath_regex_flag && bad_da_hostpath_RegExp.test(url_noservernoquery)));
            alert("bad_da_hostpath_RegExp.test(" + url_noquery + "): " + (bad_da_hostpath_regex_flag && bad_da_hostpath_RegExp.test(url_noquery)));
            alert("bad_da_RegExp.test(" + url_noserver + "): " + (bad_da_regex_flag && bad_da_RegExp.test(url_noserver)));
            alert("bad_da_RegExp.test(" + url_noscheme + "): " + (bad_da_regex_flag && bad_da_RegExp.test(url_noscheme)));
            alert("bad_url_parts_RegExp.test(" + url + "): " + (bad_url_parts_flag && bad_url_parts_RegExp.test(url)));
            alert("bad_url_regex_RegExp.test(" + url + "): " + (bad_url_regex_flag && bad_url_regex_RegExp.test(url)));
        }

        if ( (bad_da_host_exact_flag && (hasOwnProperty(bad_da_host_JSON,host_noserver)||hasOwnProperty(bad_da_host_JSON,host))) ||  // fastest test first
            (bad_da_hostpath_exact_flag && (hasOwnProperty(bad_da_hostpath_JSON,url_noservernoquery)||hasOwnProperty(bad_da_hostpath_JSON,url_noquery)) ) ||
            // test logic: only do the slower test if the host has a (non)suspect fqdn
            (bad_da_host_regex_flag && (bad_da_host_RegExp.test(host_noserver)||bad_da_host_RegExp.test(host))) ||
            (bad_da_hostpath_regex_flag && (bad_da_hostpath_RegExp.test(url_noservernoquery)||bad_da_hostpath_RegExp.test(url_noquery))) ||
            (bad_da_regex_flag && (bad_da_RegExp.test(url_noserver)||bad_da_RegExp.test(url_noscheme))) ||
            (bad_url_parts_flag && bad_url_parts_RegExp.test(url)) ||
            (bad_url_regex_flag && bad_url_regex_RegExp.test(url)) ) {
            alert_flag && alert("Blackhole: " + url + ", " + host);
            // Redefine url and host to avoid leaking information to the blackhole
            url = "http://127.0.0.1:80";
            host = "127.0.0.1";
            return blackhole;
        }
    }

    // default pass
    alert_flag && alert("Default PASS: " + url + ", " + host);
    return MyFindProxyForURL(url, host);
}

// User-supplied FindProxyForURL()
''' + self.original_FindProxyForURL_function

        self.easylist_strategy = """\
EasyList rules:
https://adblockplus.org/filters
https://adblockplus.org/filter-cheatsheet
https://opnsrce.github.io/javascript-performance-tip-precompile-your-regular-expressions
https://adblockplus.org/blog/investigating-filter-matching-algorithms

Strategies to convert EasyList rules to Javascript tests:

In general:
1. Preference for performance over 1:1 EasyList functionality
2. Limit number of rules to ~O(10k) to avoid computational burden on mobile devices
3. Exact matches: use Object hashing (very fast); use efficient NDA RegExp's for all else
4. Divide and conquer specific cases to avoid large RegExp's
5. Based on testing code performance on an iPhone: mobile Safari, Chrome with System Activity Monitor.app
6. Backstop these proxy.pac rules with Privoxy rules and a browser plugin

scheme://host/path?query ; FindProxyForURL(url, host) has full url and host strings

EasyList rules:

|| domain anchor

||host is exact e.g. ||a.b^ ? then hasOwnProperty(hash,host)
||host is wildcard e.g. ||a.* ? then RegExp.test(host)

||host/path is exact e.g. ||a.b/c? ? then hasOwnProperty(hash,url_path_noquery) [strip ?'s]
||host/path is wildcard e.g. ||a.*/c? ? then RegExp.test(url_path_noquery) [strip ?'s]

||host/path?query is exact e.g. ||a.b/c?d= ? assume none [handle small number within RegExp's]
||host/path?query is wildcard e.g. ||a.*/c?d= ? then RegExp.test(url)

url parts e.g. a.b^c&d|

All cases RegExp.test(url)
Except: |http://a.b. Treat these as domain anchors after stripping the scheme

regex e.g. /r/

All cases RegExp.test(url)

@@ exceptions

Flag as "good" versus "bad" default

Variable name conventions (example that defines the rule):

bad_da_host_exact == bad domain anchor with host/path type, exact matching with Object hash
bad_da_host_regex == bad domain anchor with host/path type, RegExp matching
"""
        return

    # Use to define js object hashes (much faster than string conversion)
    def js_init_object(self,object_name):
        obj = globals()[object_name]
        if bool(self.truncate_hash_max) and len(obj) > self.truncate_hash_max:
            warnings.warn("Truncating regex alternatives rule set '{}' from {:d} to {:d}.".format(object_name,len(obj),self.truncate_hash_max))
            obj = obj[:self.truncate_hash_max]
        return '''\

// {:d} rules:
var {}_JSON = {}{}{};
var {}_flag = {} > 0 ? true : false;  // test for non-zero number of rules
'''.format(len(obj),re.sub(r'_exact$','',object_name),'{ ',",\n".join('"{}": null'.format(x) for x in obj),' }',object_name,len(obj))

    def js_init_regexp(self,array_name,domain_anchor=False):
        global n_wildcard
        n_wildcard = 1
        domain_anchor_replace = "^" if domain_anchor else ""
        match_nothing_regexp = "/^$/"

        # no wildcard sorting
        # arr = [easylist_to_jsre(x) for x in globals()[array_name] if wildcard_test(x)]

        arr_nostar = [x for x in globals()[array_name] if not re_test(wildcard_re,x)]
        arr_star = [x for x in globals()[array_name] if re_test(wildcard_re,x)]
        def wildcard_preferences(rule):
            track_test = not re_test(re.compile(r'track',re.IGNORECASE),rule)       # MSB
            beacon_test = not re_test(re.compile(r'beacon]',re.IGNORECASE),rule)  # LSB
            stats_test = not re_test(re.compile(r'stat[is]]',re.IGNORECASE),rule)  # LSB
            analysis_test = not re_test(re.compile(r'anal[iy]]',re.IGNORECASE),rule)  # LSB
            return 8*track_test + 4*beacon_test + 2*stats_test + analysis_test
        arr_star.sort(key=wildcard_preferences)
        # Wildcard regex's use named groups. Limit their number to to an assumed maximum
        # e.g. Python's re limit is 100
        k_wildcard = 0
        rule_kdx = self.wildcard_named_group_limit
        for rule_kdx, rule in enumerate(arr_star):
            k_wildcard += len(arr_star[rule_kdx].split('*'))-1
            if k_wildcard > self.wildcard_named_group_limit: break
        arr_star = arr_star[:rule_kdx]
        arr = arr_nostar + arr_star

        if re_test(r'(?:_parts|_regex)$',array_name) and bool(self.truncate_alternatives_max) and len(arr) > self.truncate_alternatives_max:
            warnings.warn("Truncating regex alternatives rule set '{}' from {:d} to {:d}.".format(array_name,len(arr),self.truncate_alternatives_max))
            arr = arr[:self.truncate_alternatives_max]

        arr = [easylist_to_jsre(x) for x in arr]
        arr_regexp = "/" + domain_anchor_replace + "(?:" + "|".join(arr) + ")/i"
        if len(arr) == 0: arr_regexp = match_nothing_regexp

        return '''\
    
// {:d} rules as an efficient NFA RegExp:
var {}_RegExp = {};
var {}_flag = {} > 0 ? true : false;  // test for non-zero number of rules
'''.format(len(arr),re.sub(r'_regex$','',array_name),arr_regexp,array_name,len(arr))
    # end of EasyListPAC definition

# global variables and functions

last_modified_resp = lambda req: req.headers.get_all("Last-Modified")[0]
last_modified_to_utc = lambda lm: time.mktime(datetime.datetime.strptime(lm,"%a, %d %b %Y %X GMT").timetuple())
file_to_utc = lambda f: time.mktime(datetime.datetime.utcfromtimestamp(os.path.getmtime(f)).timetuple())

user_agent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'

# Monkey patch `re.sub` (***groan***)
# See https://gist.github.com/gromgull/3922244
if (sys.version_info < (3, 5)):
    def re_sub(pattern, replacement, string):
        def _r(m):
            # Now this is ugly.
            # Python has a "feature" where unmatched groups return None
            # then re.sub chokes on this.
            # see http://bugs.python.org/issue1519638

            # this works around and hooks into the internal of the re module...

            # the match object is replaced with a wrapper that
            # returns "" instead of None for unmatched groups

            class _m():
                def __init__(self, m):
                    self.m = m
                    self.string = m.string

                def group(self, n):
                    return m.group(n) or ""

            return re._expand(pattern, _m(m), replacement)

        return re.sub(pattern, _r, string)
else:
    re_sub = re.sub

# print(re_sub('(ab)|(a)', r'(1:\1 2:\2)', 'abc'))
# prints '(1:ab 2:)c'

# EasyList regular expressions

comment_re = re.compile(r'^\s*?!')   # ! commment
configuration_re = re.compile(r'^\s*?\[[^]]*?\]')  # [Adblock Plus 2.0]
easylist_opts = r'~?\b(?:third\-party|domain|script|image|stylesheet|object(?!-subrequest)|object\-subrequest|xmlhttprequest|subdocument|ping|websocket|webrtc|document|elemhide|generichide|genericblock|other|sitekey|match-case|collapse|donottrack|popup|media|font)\b'
option_re = re.compile(r'^(.*?)\$(' + easylist_opts + r'.*?)$')
# regex's used to exclude options for specific cases
alloption_exception_re = re.compile(easylist_opts)  # discard all options from rules
not3dimppupos_option_exception_re = re.compile(r'~?\b(?:domain|script|stylesheet|object(?!-subrequest)|xmlhttprequest|subdocument|ping|websocket|webrtc|document|elemhide|generichide|genericblock|other|sitekey|match-case|collapse|donottrack|media|font)\b')
not3dimppuposgh_option_exception_re = re.compile(r'~?\b(?:domain|script|stylesheet|object(?!-subrequest)|xmlhttprequest|subdocument|ping|websocket|webrtc|document|elemhide|genericblock|other|sitekey|match-case|collapse|donottrack|media|font)\b')
thrdp_im_pup_os_option_re = re.compile(r'\b(?:third\-party|image|popup|object\-subrequest)\b')
selector_re = re.compile(r'^(.*?)#\@?#*?.*?$') # #@##div [should be #+?, but old style still used]
regex_re = re.compile(r'^\@{0,2}\/(.*?)\/$')
wildcard_begend_re = re.compile(r'^(?:\**?([^*]*?)\*+?|\*+?([^*]*?)\**?)$')
wild_anch_sep_exc_re = re.compile(r'[*|^@]')
wild_sep_exc_noanch_re = re.compile(r'(?:[*^@]|\|[\s\S])')
exception_re = re.compile(r'^@@(.*?)$')
wildcard_re = re.compile(r'\*+?')
httpempty_re = re.compile(r'^\|?https?://$')
# Note: assume path end rules the end in '/' are partial, not exact, e.g. host.com/path/
pathend_re = re.compile(r'(?:\||\.(?:jsp?|php|xml|jpe?g|png|p?gif|img|swf|flv|[sp]?html?|f?cgi|pl?|aspx|ashx|css|jsonp?|asp|search|cfm|ico|act|act(?:ion)?|spy|do|stm|cms|txt|imu|dll|io|smjs|xhr|ount|bin|py|dyn|gne|mvc|lv|nap|jam|nhn))$',re.IGNORECASE)

domain_anch_re = re.compile(r'^\|\|(.+?)$')
# omit scheme from start of rule -- this will also be done in JS for efficiency
scheme_anchor_re = re.compile(r'^(\|?(?:[\w*+-]{1,15})?://)');  # e.g. '|http://' at start

# (Almost) fully-qualified domain name extraction (with EasyList wildcards)
# Example case: banner.3ddownloads.com^
da_hostonly_re = re.compile(r'^((?:[\w*-]+\.)+[a-zA-Z0-9*-]{1,24}\.?)(?:$|[/^?])$')
da_hostpath_re = re.compile(r'^((?:[\w*-]+\.)+[a-zA-Z0-9*-]{1,24}\.?[\w~%./^*-]+?)\??$')

ipv4_re = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')

host_path_parts_re = re.compile(r'^(?:https?://)?((?:\d{1,3}\.){3}\d{1,3}|(?:[\w-]+\.)+[a-zA-Z0-9-]{2,24}\.?)?([\S]+)?',re.IGNORECASE)

punct_str = r'][{}()<>.,;:?/~!#$%^&*_=+`\'"|\s-'
punct_class = r'[{}]'.format(punct_str)
nopunct_class = r'[^{}]'.format(punct_str)
specialword_re = r'<\w+>'
hostpunct_str = punct_str[:-1]  # everything but '-'
hostpunct_class = r'[{}]'.format(hostpunct_str)

# regex logic: (keep1|keep2)|([::discard class::]+?)
# (<\w+>|\b(?:\w+[.])+[a-zA-Z0-9-]{2,24}\b)|([][()<>.;-]+?)
punct_deletepreserve_re = r'({}|\b{}\b)|({}+?)'.format(specialword_re,ipv4_re.pattern,punct_class)
punct_deletepreserve_reprog = re.compile(punct_deletepreserve_re)
punct_deletepreserve_replace = '\\1 '
hostpunct_deletepreserve_re = r'({}|\b{}\b)|({}+?)'.format(specialword_re,ipv4_re.pattern,hostpunct_class)
hostpunct_deletepreserve_reprog = re.compile(hostpunct_deletepreserve_re)
whitespace_reprog = re.compile(r'\s+')
whitespace_replace = ' '

def exception_filter(line):
    return bool(exception_re.search(line))
def line_hostpath_rule(line):
   line = exception_re.sub('\\1',line)
   line = domain_anch_re.sub('\\1',line)
   line = option_re.sub('\\1',line)
   return line
def punct_delete(line,punct_re=punct_deletepreserve_reprog):
    res = line
    res = re_sub(punct_re,punct_deletepreserve_replace,res)
    res = re_sub(whitespace_reprog,whitespace_replace,res)
    return res
def rule_tokenizer(rule):
    rule = line_hostpath_rule(rule)
    host_part = re_sub(host_path_parts_re,'\\1',rule)
    path_part = re_sub(host_path_parts_re,'\\2',rule)
    toks = ' '.join([punct_delete(host_part,punct_re=hostpunct_deletepreserve_reprog), punct_delete(path_part)]).strip()
    toks = re_sub(whitespace_reprog,whitespace_replace,toks)
    return toks
easylist_name_opts_re = re.compile(r'^~?\b(third\-party|domain|script|image|stylesheet|object(?!-subrequest)|object\-subrequest|xmlhttprequest|subdocument|ping|websocket|webrtc|document|elemhide|generichide|genericblock|other|sitekey|match-case|collapse|donottrack|popup|media|font)(?:=.+?)?$')
def option_tokenizer(opts):
    toks = ' '.join([easylist_name_opts_re.sub('\\1',o) for o in opts.split(',')])
    return toks

# use or not use regular expression rules of any kind
def regex_ignore_test(line,opts=''):
    res = False  # don't ignore any rule
    # ignore wildcards and anchors
    # res = re_test(r'[*^]',line)
    return res

def re_test(regex,string):
    if isinstance(regex,str): regex = re.compile(regex)
    return bool(regex.search(string))

# Logistic Regression functions

# feature vector hashes
# JSON structure: {"token": { "column": list of int, "count": list of int, "row_index": int }
# create adjacency lists for memory efficient sparse COO array construction

default_row = {"column": [], "count": []}
def feature_vector_append_column(rule,opts,col,feature_vector={}):
    # rule grams
    toks = re.split(r'\s+',rule_tokenizer(rule))
    for k in range(len(toks)):
        # 1- and 2-grams
        grams = [toks[k], toks[k] + ' ' + toks[k + 1]] if k < len(toks) - 1 else [toks[k]]
        feature_vector_append_grams(grams, col, feature_vector, weight=1/np.sqrt(len(toks)))
    if bool(opts):
        # option tokens (1-grams)
        grams = ['option: ' + x for x in re.split(r'\s+', option_tokenizer(opts))]
        feature_vector_append_grams(grams, col, feature_vector, weight=min(0.5, 1.e-1/np.sqrt(len(grams))))
    if len(toks) <= 3:
        """Add information from available options and high weight regex matches."""
        # regex tokens used to relate for short, unique rules
        grams = []
        for regex in high_weight_regex:
            if bool(regex.search(rule)): grams.append('regex: ' + regex.pattern)
        if bool(grams): feature_vector_append_grams(grams, col, feature_vector, weight=1/np.sqrt(len(grams)))

def feature_vector_append_grams(grams, col, feature_vector={}, weight=1.):
    for ky in grams:
        feature_vector[ky] = feature_vector.get(ky, copy.deepcopy(default_row))
        if not feature_vector[ky]["column"] or feature_vector[ky]["column"][-1] is not col:
            feature_vector[ky]["column"].append(col)
            feature_vector[ky]["count"].append(0)
        feature_vector[ky]["count"][-1] += weight

# store feature vectors as sparse arrays
def fv_to_mat(feature_vector=copy.deepcopy(default_row),rules=[]):
    """Compute sparse, transposed, CSR matrix and row hash from a feature vector."""
    row_hash = {}
    rows = []
    cols = []
    vals = []
    for i, tok in enumerate(feature_vector):
        feature_vector[tok]["row_index"] = i
        row_hash[i] = tok
        j_new = feature_vector[tok]["column"]
        i_new = [i]*len(j_new)
        v_new = feature_vector[tok]["count"]
        rows += i_new
        cols += j_new
        vals += v_new
    fv_mat = sps.coo_matrix((vals,(cols,rows)),shape=(len(rules),len(feature_vector)),dtype=np.float).tocsr()
    return fv_mat, row_hash

# convert EasyList wildcard '*', separator '^', and anchor '|' to regexp; ignore '?' globbing
# http://blogs.perl.org/users/mauke/2017/05/converting-glob-patterns-to-efficient-regexes-in-perl-and-javascript.html
# For efficiency this these are converted in Python; observed to be important in iSO kernel

# var domain_anchor_RegExp = RegExp("^\\\\|\\\\|");
# // performance: use a simplified, less inclusive of subdomains, regex for domain anchors
# // also assume that RexgExp("^https?//") stripped from url string beforehand
# //var domain_anchor_replace = "^(?:[\\\\w\\-]+\\\\.)*?";
# var domain_anchor_replace = "^";
# var n_wildcard = 1;
# function easylist2re(pat) {
#     function tr(pat) {
#         return pat.replace(/[-\\/.?:!+^|$()[\\]{}]/g, function (m0, mp, ms) {  // url, regex, EasyList special chars
#             // res = m0 === "?" ? "[\\s\\S]" : "\\\\" + m0;
#             // https://adblockplus.org/filters#regexps, separator "^" == [^\\w.%-]
#             var res = "\\\\" + m0;
#             switch (m0) {
#             case "^":
#                 res = "[^\\\\w.%-]";
#                 break;
#             case "|":
#                 res = mp + m0.length === ms.length ? "$" : "^";
#                 break;
#             default:
#                 res = "\\\\" + m0;  // escape special characters
#             }
#             return res;
#         });
#     }
#
#     // EasyList domain anchor "||"
#     var bos = "";
#     if (domain_anchor_RegExp.test(pat)) {
#         pat = pat.replace(domain_anchor_RegExp, "");  // strip "^||"
#         bos = domain_anchor_replace;
#     }
#
#     // EasyList wildcards '*', separators '^', and start/end anchors '|'
#     // define n_wildcard outside the function for concatenation of these patterns
#     // var n_wildcard = 1;
#     pat = bos + pat.replace(/\\W[^*]*/g, function (m0, mp, ms) {
#         if (m0.charAt(0) !== "*") {
#             return tr(m0);
#         }
#         // var eos = mp + m0.length === ms.length ? "$" : "";
#         var eos = "";
#         return "(?=([\\\\s\\\\S]*?" + tr(m0.substr(1)) + eos + "))\\\\" + n_wildcard++;
#     });
#     return pat;
# }

n_wildcard = 1
def easylist_to_jsre(pat):
    def re_easylist(match):
        mg = match.group()[0]
        # https://adblockplus.org/filters#regexps, separator "^" == [^\\w.%-]
        if mg == "^":
            res = "[^\\w.%-]"
        elif mg == "|":
            res = "^" if match.span()[0] == 0 else "$"
        else:
            res = '\\' + mg
        return res
    def tr(pat):
        return re.sub(r'[-\/.?:!+^|$()[\]{}]', re_easylist, pat)
    def re_wildcard(match):
        global n_wildcard
        mg = match.group()
        if mg[0] != "*": return tr(mg)
        res = '(?=([\\s\\S]*?' + tr(mg[1:]) + '))\\' + '{:d}'.format(n_wildcard)
        n_wildcard += 1
        return res
    domain_anchor_replace = "^"
    bos = ''
    if re_test(domain_anch_re,pat):
        pat = domain_anch_re.sub('\\1',pat)
        bos = domain_anchor_replace
    pat = bos + re.sub(r'(\W[^*]*)', re_wildcard, pat)
    return pat

def ordered_unique_all_js_var_lists():
    global good_da_host_exact
    global good_da_host_regex
    global good_da_hostpath_exact
    global good_da_hostpath_regex
    global good_da_regex
    global good_da_host_exceptions_exact

    global bad_da_host_exact
    global bad_da_host_regex
    global bad_da_hostpath_exact
    global bad_da_hostpath_regex
    global bad_da_regex

    global good_url_parts
    global bad_url_parts
    global good_url_regex
    global bad_url_regex

    good_da_host_exact = ordered_unique_nonempty(good_da_host_exact)
    good_da_host_regex = ordered_unique_nonempty(good_da_host_regex)
    good_da_hostpath_exact = ordered_unique_nonempty(good_da_hostpath_exact)
    good_da_hostpath_regex = ordered_unique_nonempty(good_da_hostpath_regex)
    good_da_regex = ordered_unique_nonempty(good_da_regex)
    good_da_host_exceptions_exact = ordered_unique_nonempty(good_da_host_exceptions_exact)

    bad_da_host_exact = ordered_unique_nonempty(bad_da_host_exact)
    bad_da_host_regex = ordered_unique_nonempty(bad_da_host_regex)
    bad_da_hostpath_exact = ordered_unique_nonempty(bad_da_hostpath_exact)
    bad_da_hostpath_regex = ordered_unique_nonempty(bad_da_hostpath_regex)
    bad_da_regex = ordered_unique_nonempty(bad_da_regex)

    good_url_parts = ordered_unique_nonempty(good_url_parts)
    bad_url_parts = ordered_unique_nonempty(bad_url_parts)
    good_url_regex = ordered_unique_nonempty(good_url_regex)
    bad_url_regex = ordered_unique_nonempty(bad_url_regex)

# ordered uniqueness, https://stackoverflow.com/questions/12897374/get-unique-values-from-a-list-in-python
ordered_unique_nonempty = lambda listable: fnt.reduce(lambda l, x: l.append(x) or l if x not in l and bool(x) else l, listable, [])

# list variables based on EasyList strategies above
# initial values prepended before EasyList rules
# pass updates and services from these domains
# handle organization-specific ad and tracking servers in later commit
good_da_host_exact = ['apple.com',
                      'icloud.com',
                      'apple-dns.net',
                      'swcdn.apple.com',
                      'init.itunes.apple.com',  # use nslookup to determine canonical names
                      'init-cdn.itunes-apple.com.akadns.net',
                      'itunes.apple.com.edgekey.net',
                      'setup.icloud.com',
                      'p32-escrowproxy.icloud.com',
                      'p32-escrowproxy.fe.apple-dns.net',
                      'keyvalueservice.icloud.com',
                      'keyvalueservice.fe.apple-dns.net',
                      'p32-bookmarks.icloud.com',
                      'p32-bookmarks.fe.apple-dns.net',
                      'p32-ckdatabase.icloud.com',
                      'p32-ckdatabase.fe.apple-dns.net',
                      'configuration.apple.com',
                      'configuration.apple.com.edgekey.net',
                      'mesu.apple.com',
                      'mesu-cdn.apple.com.akadns.net',
                      'mesu.g.aaplimg.com',
                      'gspe1-ssl.ls.apple.com',
                      'gspe1-ssl.ls.apple.com.edgekey.net',
                      'api-glb-bos.smoot.apple.com',
                      'query.ess.apple.com',
                      'query-geo.ess-apple.com.akadns.net',
                      'query.ess-apple.com.akadns.net',
                      'setup.fe.apple-dns.net',
                      'gsa.apple.com',
                      'gsa.apple.com.akadns.net',
                      'icloud-content.com',
                      'usbos-edge.icloud-content.com',
                      'usbos.ce.apple-dns.net',
                      'lcdn-locator.apple.com',
                      'lcdn-locator.apple.com.akadns.net',
                      'lcdn-locator-usuqo.apple.com.akadns.net',
                      'cl1.apple.com',
                      'cl2.apple.com',
                      'cl3.apple.com',
                      'cl4.apple.com',
                      'cl5.apple.com',
                      'cl1-cdn.origin-apple.com.akadns.net',
                      'cl2-cdn.origin-apple.com.akadns.net',
                      'cl3-cdn.origin-apple.com.akadns.net',
                      'cl4-cdn.origin-apple.com.akadns.net',
                      'cl5-cdn.origin-apple.com.akadns.net',
                      'cl1.apple.com.edgekey.net',
                      'cl2.apple.com.edgekey.net',
                      'cl3.apple.com.edgekey.net',
                      'cl4.apple.com.edgekey.net',
                      'cl5.apple.com.edgekey.net',
                      'xp.apple.com',
                      'xp.itunes-apple.com.akadns.net',
                      'mt-ingestion-service-pv.itunes.apple.com',
                      'p32-sharedstreams.icloud.com',
                      'p32-sharedstreams.fe.apple-dns.net',
                      'p32-fmip.icloud.com',
                      'p32-fmip.fe.apple-dns.net',
                      'gsp-ssl.ls.apple.com',
                      'gsp-ssl.ls-apple.com.akadns.net',
                      'gsp-ssl.ls2-apple.com.akadns.net',
                      'gspe35-ssl.ls.apple.com',
                      'gspe35-ssl.ls-apple.com.akadns.net',
                      'gspe35-ssl.ls.apple.com.edgekey.net',
                      'gsp64-ssl.ls.apple.com',
                      'gsp64-ssl.ls-apple.com.akadns.net',
                      'mt-ingestion-service-st11.itunes.apple.com',
                      'mt-ingestion-service-st11.itunes-apple.com.akadns.net',
                      'microsoft.com', 'mozilla.com', 'mozilla.org']
good_da_host_regex = []
good_da_hostpath_exact = []
good_da_hostpath_regex = []
good_da_regex = []
bad_da_host_exact = []
bad_da_host_regex = []
bad_da_hostpath_exact = []
bad_da_hostpath_regex = []
bad_da_regex = []
good_url_parts = []
bad_url_parts = []
good_url_regex = []
bad_url_regex = []

# provide explicit expceptions to good hosts or domains, e.g. iad.apple.com
good_da_host_exceptions_exact = [ 'iad.apple.com',
                                  'iadsdk.apple.com',
                                  'iadsdk.apple.com.edgekey.net',
                                  'bingads.microsoft.com',
                                  'azure.bingads.trafficmanager.net',
                                  'choice.microsoft.com',
                                  'choice.microsoft.com.nsatc.net',
                                  'corpext.msitadfs.glbdns2.microsoft.com',
                                  'corp.sts.microsoft.com',
                                  'df.telemetry.microsoft.com',
                                  'diagnostics.support.microsoft.com',
                                  'feedback.search.microsoft.com',
                                  'i1.services.social.microsoft.com',
                                  'i1.services.social.microsoft.com.nsatc.net',
                                  'redir.metaservices.microsoft.com',
                                  'reports.wes.df.telemetry.microsoft.com',
                                  'services.wes.df.telemetry.microsoft.com',
                                  'settings-sandbox.data.microsoft.com',
                                  'settings-win.data.microsoft.com',
                                  'sqm.df.telemetry.microsoft.com',
                                  'sqm.telemetry.microsoft.com',
                                  'sqm.telemetry.microsoft.com.nsatc.net',
                                  'statsfe1.ws.microsoft.com',
                                  'statsfe2.update.microsoft.com.akadns.net',
                                  'statsfe2.ws.microsoft.com',
                                  'survey.watson.microsoft.com',
                                  'telecommand.telemetry.microsoft.com',
                                  'telecommand.telemetry.microsoft.com.nsatc.net',
                                  'telemetry.urs.microsoft.com',
                                  'vortex.data.microsoft.com',
                                  'vortex-sandbox.data.microsoft.com',
                                  'vortex-win.data.microsoft.com',
                                  'cy2.vortex.data.microsoft.com.akadns.net',
                                  'watson.microsoft.com',
                                  'watson.ppe.telemetry.microsoft.com'
                                  'watson.telemetry.microsoft.com',
                                  'watson.telemetry.microsoft.com.nsatc.net',
                                  'wes.df.telemetry.microsoft.com',
                                  'win10.ipv6.microsoft.com',
                                  'www.bingads.microsoft.com',
                                  'survey.watson.microsoft.com' ]

# Long regex filter """here""" documents

# ignore any rules following comments with these strings, until the next non-ignorable comment
commentname_sections_ignore_re = r'(?:{})'.format('|'.join(re.sub(r'([.])','\\.',x) for x in '''\
gizmodo.in
shink.in
project-free-tv.li
vshare.eu
pencurimovie.ph
filmlinks4u.is
Spiegel.de
bento.de
German
French
Arabic
Armenian
Belarusian
Bulgarian
Chinese
Croatian
Czech
Danish
Dutch
Estonian
Finnish
Georgian
Greek
Hebrew
Hungarian
Icelandic
Indian
Indonesian
Italian
Japanese
Korean
Latvian
Lithuanian
Norwegian
Persian
Polish
Portuguese
Romanian
Russian
Serbian
Singaporean
Slovene
Slovak
Spanish
Swedish
Thai
Turkish
Ukranian
Ukrainian
Vietnamese
Gamestar.de
Focus.de
tvspielfilm.de
Prosieben
Wetter.com
Woxikon.de
Fanfiktion.de
boote-forum.de
comunio.de
planetsnow.de'''.split('\n')))

# include these rules, no matter their priority
# necessary to include desired rules that fall below the threshold for a reasonably-sized PAC
include_these_good_rules = []
include_these_bad_rules = [x for x in """\
/securepubads.
||google.com/pagead""".split('\n') if not bool(re.search(r'^\s*?(?:#|$)',x))]

# regex's for highly weighted rules
high_weight_regex_strings = """\
trac?k
beacon
stat[is]?
anal[iy]
goog
facebook
yahoo
amazon
adob
msn
# 2-grams
goog\\S+?ad
amazon\\S+?ad
yahoo\\S+?ad
facebook\\S+?ad
adob\\S+?ad
msn\\S+ad
doubleclick
cooki
twitter
krxd
pagead
syndicat
(?:\\bad|ad\\b)
securepub
static
\\boas\\b
ads
cdn
cloud
banner
financ
share
traffic
creativ
media
host
affil
^mob
data
your?
watch
survey
stealth
invisible
brand
site
merch
kli[kp]
clic?k
popup
log
assets
count
metric
score
event
tool
quant
chart
opti?m
partner
sponsor
affiliate"""

high_weight_regex = [re.compile(x,re.IGNORECASE) for x in high_weight_regex_strings.split('\n') if not bool(re.search(r'^\s*?(?:#|$)',x))]

# regex to limit regex filters (bootstrapping in part from securemecca.com PAC regex keywords)
if False:
    badregex_regex_filters = ''  # Accept everything
else:
    badregex_regex_filters = high_weight_regex_strings + '\n' + '''\
cooki
pagead
syndicat
(?:\\bad|ad\\b)
cdn
cloud
banner
image
img
pop
game
free
financ
film
fast
farmville
fan
exp
share
cash
money
dollar
buck
dump
deal
daily
content
kick
down
file
video
score
partner
match
ifram
cam
widget
monk
rapid
platform
google
follow
shop
love
content
#^(\\d{1,3})\\.(\d{1,3})\\.(\\d{1,3})\.(\\d{1,3})$
#^([A-Za-z]{12}|[A-Za-z]{8}|[A-Za-z]{50})\\.com$
smile
happy
traffic
dash
board
tube
torrent
down
creativ
host
affil
\\.(biz|ru|tv|stream|cricket|online|racing|party|trade|webcam|science|win|accountant|loan|faith|cricket|date)
^mob
join
data
your?
watch
survey
stealth
invisible
social
brand
site
script
xchang
merch
kli(k|p)
clic?k
zip
invest
arstech
buzzfeed
imdb
twitter
baidu
yandex
youtube
ebay
discovercard
chase
hsbc
usbank
santander
kaspersky
symantec
brightcove
hidden
invisible
macromedia
flash
[^i]scan[^dy]
secret
skype
tsbbank
tunnel
ubs\\.com
unblock
unlock
usaa\\.com
usbank\\.com
ustreas\\.gov
ustreasury
verifiedbyvisa\\.com
viagra
wachovia
wellsfargo\\.com
westernunion
windowsupdate
plugin
nielsen
oas-config
oas\\/oas
pix
video-plugin
videodownloader
visit
voxmedia\\.com
vtrack\\.php
w3track\\.com
web_?ad
webiq
weblog
webtrek
webtrend
wget\\.exe
widgets
winstart\\.exe
winstart\\.zip
wired\\.com
ad-limits\\.js
ad-manager
ad_engine
adx\\.js
\\.bat
\\.bin
[^ck]anal[^_]
\\.com\/a\\.gif
\\.com\/p\\.gif
\\.com\\.au\\/ads
\\.cpl
[^bhmz]eros
\\.exe
\\.exe
\\.msi
\\.net\\/p\\.gif
\\.pac
\\.pdf
\\.pdf\\.exe
\\.rar
\\.scr
\\.sh
transparent1x1\\.gif
\\/travidia
__utm\\.js
whv2_001\\.js
xtcore\\.js
\\.zip
sharethis\\.com
stats\\.wp\\.com
[^i]crack
virgins\\.com
\\.xyz
shareasale\\.com
financialcontent\\.com'''

badregex_regex_filters = '\n'.join(x for x in badregex_regex_filters.split('\n') if not bool(re.search(r'^\s*?(?:#|$)',x)))
badregex_regex_filters_re = re.compile(r'(?:{})'.format('|'.join(badregex_regex_filters.split('\n'))),re.IGNORECASE)

if __name__ == "__main__":
    res = EasyListPAC()

sys.exit()
