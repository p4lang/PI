/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include "web_server.h"
#include "simple_router_mgr.h"

#include <sstream>

#include <microhttpd.h>

#define POSTBUFFERSIZE  16384
#define MAXNAMESIZE     20
#define MAXANSWERSIZE   1024
#define GET             0
#define POST            1

namespace {

struct connection_info_struct {
  int connectiontype;
  WebServer *web_server;
  std::string counter_name;
  size_t counter_index;
  std::string counter_str;
  std::string new_json_name;
  std::string buffer;
  std::string update_error;
  struct MHD_PostProcessor *postprocessor;
};

const char *monitor_page_template = "<html><body>\
<h1>L3 Controller monitor page</h1>\
Current JSON is '%s', do you want to update a new file?<br>\
<form action=\"/jsonpost\" method=\"post\" enctype=\"multipart/form-data\">\
  <input type=\"file\" name=\"new_json\">\
  <input type=\"submit\" value=\" Submit \">\
</form>\
%s<br>\
Do you want to query a counter?<br>\
<form action=\"/counterpost\" method=\"post\">\
<input name=\"counter_name\" type=\"text\" value=\"%s\">\
<input name=\"counter_index\" type=\"number\" value=\"%d\">\
<input type=\"submit\" value=\" Submit \"></form>\
%s<br>\
</body></html>";
const char *errorpage =
    "<html><body>This doesn’t seem to be right.</body></html>";

char *generate_page(WebServer *web_server,
                    connection_info_struct *con_info = NULL) {
  char *answerstring = new char[MAXANSWERSIZE];
  if (!answerstring) return NULL;
  const char *counter_str = "";
  const char *counter_name = "";
  int counter_index = 0;
  const char *update_error = "";
  if (con_info) {
    assert(web_server == con_info->web_server);
    counter_str = con_info->counter_str.c_str();
    counter_name = con_info->counter_name.c_str();
    counter_index = static_cast<int>(con_info->counter_index);
    update_error = con_info->update_error.c_str();
  }
  snprintf(answerstring, MAXANSWERSIZE, monitor_page_template,
           web_server->get_json_name().c_str(), update_error,
           counter_name, counter_index, counter_str);
  return answerstring;
}

int send_page(struct MHD_Connection *connection, const char *page) {
  int ret;
  struct MHD_Response *response;
  response = MHD_create_response_from_buffer(strlen(page), (void *)page,
                                             MHD_RESPMEM_PERSISTENT);
  if (!response) return MHD_NO;
  ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
  MHD_destroy_response(response);
  return ret;
}

int iterate_post(void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
                 const char *filename, const char *content_type,
                 const char *transfer_encoding, const char *data, uint64_t off,
                 size_t size) {
  connection_info_struct *con_info = static_cast<connection_info_struct *>(
      coninfo_cls);
  if (!strncmp(key, "counter_name", sizeof "counter_name")) {
    if ((size > 0) && (size <= MAXNAMESIZE)) {
      con_info->counter_name = std::string(data, size);
    } else {
      return MHD_NO;
    }
    return MHD_YES;
  } else if (!strncmp(key, "counter_index", sizeof "counter_index")) {
    try {
      con_info->counter_index = std::stoi(std::string(data));
    } catch (...) {
      return MHD_NO;
    }
    return MHD_YES;
  } else if (!strncmp(key, "new_json", sizeof "new_json")) {
    con_info->buffer.append(data, size);
    con_info->new_json_name = std::string(filename);
    return MHD_YES;
  }
  return MHD_NO;
}

void request_completed(void *cls, struct MHD_Connection *connection,
                       void **con_cls, enum MHD_RequestTerminationCode toe) {
  connection_info_struct *con_info = static_cast<connection_info_struct *>(
      *con_cls);
  if (!con_info) return;
  if (con_info->connectiontype == POST) {
    MHD_destroy_post_processor(con_info->postprocessor);
  }
  delete con_info;
  *con_cls = NULL;
}

int perform_requested_ops_and_respond(struct MHD_Connection *connection,
                                      connection_info_struct *con_info) {
  WebServer *server = con_info->web_server;
  if (con_info->new_json_name != "") {
    int rc = server->update_json_config(con_info->buffer);
    if (rc) {
      con_info->update_error = "Error during config update";
    } else {
      server->set_json_name(con_info->new_json_name);
    }
  }
  if (con_info->counter_name != "") {
    uint64_t packets = 0;
    uint64_t bytes = 0;
    std::string counter_name = con_info->counter_name;
    size_t index = con_info->counter_index;
    int rc = server->query_counter(counter_name, index, &packets, &bytes);
    if (rc) {
      con_info->counter_str = "Error when trying to read " + counter_name;
    } else {
      std::stringstream ss;
      ss << counter_name << "[" << index << "] = " << packets << " (packets), "
         << bytes << " (bytes)";
      con_info->counter_str = ss.str();
    }
  }
  return send_page(connection, generate_page(con_info->web_server, con_info));
}

int answer_to_connection(void *cls, struct MHD_Connection *connection,
                         const char *url, const char *method,
                         const char *version, const char *upload_data,
                         size_t *upload_data_size, void **con_cls) {
  WebServer *server = static_cast<WebServer *>(cls);
  if (!*con_cls) {
    struct connection_info_struct *con_info;
    con_info = new connection_info_struct;
    if (!con_info) return MHD_NO;
    con_info->counter_str = "";
    con_info->counter_name = "";
    con_info->counter_index = 0;
    con_info->new_json_name = "";
    con_info->buffer = "";
    con_info->update_error = "";
    con_info->web_server = server;
    if (!strncmp (method, "POST", sizeof "POST")) {
      con_info->postprocessor = MHD_create_post_processor(
          connection, POSTBUFFERSIZE, iterate_post,
          static_cast<void *>(con_info));
      if (!con_info->postprocessor) {
        delete con_info;
        return MHD_NO;
      }
      con_info->connectiontype = POST;
    } else {
      con_info->connectiontype = GET;
    }
    *con_cls = static_cast<void *>(con_info);
    return MHD_YES;
  }
  if (!strncmp(method, "GET", sizeof "GET"))
    return send_page(connection, generate_page(server));
  if (!strncmp(method, "POST", sizeof "POST")) {
    connection_info_struct *con_info = static_cast<connection_info_struct *>(
        *con_cls);
    if (*upload_data_size != 0) {
      MHD_post_process(con_info->postprocessor, upload_data, *upload_data_size);
      *upload_data_size = 0;
      return MHD_YES;
    } else {
      return perform_requested_ops_and_respond(connection, con_info);
    }
  }
  return send_page(connection, errorpage);
}

}  // namespace

WebServer::WebServer(SimpleRouterMgr *simple_router_mgr, int port)
    : simple_router_mgr(simple_router_mgr), port(port) { }

WebServer::~WebServer() {
  MHD_stop_daemon(daemon);
}

int
WebServer::start() {
  daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION, port, NULL, NULL,
                            &answer_to_connection, static_cast<void *>(this),
                            MHD_OPTION_NOTIFY_COMPLETED, request_completed,
                            NULL, MHD_OPTION_END);
  return (daemon != NULL);
}

void
WebServer::set_json_name(const std::string &json_name) {
  std::unique_lock<std::mutex> lock(mutex);
  current_json = json_name;
}

std::string
WebServer::get_json_name() const {
  std::unique_lock<std::mutex> lock(mutex);
  return current_json;
}

int
WebServer::query_counter(const std::string &counter_name, size_t index,
                         uint64_t *packets, uint64_t *bytes) {
  return simple_router_mgr->query_counter(counter_name, index, packets, bytes);
}

int
WebServer::update_json_config(const std::string &config_buffer) {
  return simple_router_mgr->update_config(config_buffer);
}
