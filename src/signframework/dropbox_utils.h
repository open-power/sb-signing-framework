/* Copyright 2017 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/inotify.h>

#include "framework_utils.h"

#ifndef DROPBOX_UTILS_H
#define DROPBOX_UTILS_H


/// Initialize the dropbox
int dropboxInit(FrameworkConfig *frameworkConfig);
/// Close all active dropbox watchers
int dropboxShutdown(FrameworkConfig *frameworkConfig);

/// Process the inotify event
int processEvent(FrameworkConfig *frameworkConfig, struct inotify_event *i,
                 int* stop, int* restart);

int sendResult(DropboxRequest* requestParms);
#endif
