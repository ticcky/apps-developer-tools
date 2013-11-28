var DEBUG = true;

var WHY_WE_ASK = {
  manifest: function(q) {
    return '<small><p class="text-muted">We ask, because we detected that you have the permission <code>' + q.triggers.join() + '</code> in your original manifest.</p></small>';
  },
  runtime: function(q) {
    return '<small><p class="text-muted">We ask, because we detected that you used the <code>chrome.tabs</code> API, but only if you access the restricted fields mentioned above, you need to ask for <code>tabs</code> permission.</p></small>';
  }
}

D_CHROME_API = "chrome_api";

function getActivityArgUrl(activity, ndx) {
  var args = JSON.parse(activity.args);
  var url = args[ndx];
  if(url === "<arg_url>") {
    url = activity.argUrl;
  }
  return url;
}

// Permission building helper functions.
function buildRegexpApiCallActivityHandler(regexp, perm) {
  return function(perm, activity) {
    if(activity.activityType === "api_call") {
      if(regexp.exec(activity.apiCall) !== null) {
        onPermissionDetected(perm);
      }
    }
  }
}

function addPermissionManifestLoadedHandler(perm) {
  if(recordedData.manifest.permissions.indexOf(perm) !== -1) {
    addPermission(perm);
  }

}

function standardChromePermission(perm) {
  PERMISSIONS[perm] = {
    activity_handler: buildRegexpApiCallActivityHandler(new RegExp("^" + perm))
  }
}

function activityBasedPermission(perm, fn) {
  PERMISSIONS[perm] = {
    activity_handler: fn
  }
}

function questionBasedPermission(perm, question, fn) {
  PERMISSIONS[perm] = {
    question_answered_handler: function(perm, q_id, answer) {
      if(q_id === question) {
        return fn(perm, q_id, answer)
      }
    },
    manifest_loaded_handler: function(perm) {
      if(recordedData.manifest.permissions.indexOf(perm) !== -1) {
        addQuestion(question, WHY_WE_ASK["manifest"]);
        addPermission(perm);
      }
    }
  }
}

// Build permissions.
var PERMISSIONS = {};

PERMISSIONS["activeTab"] = {
    manifest_loaded_handler: function() {
      if(recordedData.manifest.permissions.indexOf("<all_urls>") !== -1 &&
         recordedData.manifest.browserAction !== undefined) {
        addQuestion("activeTab", "");
      }
    },
    question_answered_handler: function(perm, q_id, answer) {
      if(q_id === "activeTab") {
        if(answer === "yes") {
          onPermissionDetected("activeTab");
          onPermissionUndetected("<all_urls>");
        } else {
          onPermissionUndetected("activeTab");
          onPermissionDetected("<all_urls>");
        }
      }
    }
};

PERMISSIONS["tabs"] = {
  activity_handler: function(perm, activity) {
    if(activity.activityType === "api_call") {
      if(/^tabs/.exec(activity.apiCall) !== null) {
        addQuestion("tabs", WHY_WE_ASK["runtime"]);
      }

      if(/^tabs.executeScript/.exec(activity.apiCall) !== null) {
        var url = getActivityArgUrl(activity, 0);
        var hostPerm = extractPermHost(url);
        onPermissionDetected(hostPerm);
      }
    }
  },
  question_answered_handler: function(perm, q_id, answer) {
    if(q_id === "tabs") {
      if(answer === "yes") {
        onPermissionDetected("tabs");
      } else {
        onPermissionUndetected("tabs");
      }
    }
  },
  manifest_loaded_handler: function(perm) {
      if(recordedData.manifest.permissions.indexOf(perm) !== -1) {
        addPermission(perm);
      }
    }
}

PERMISSIONS["<host_and_csp>"] = {
  activity_handler: function(perm, activity) {
    if(activity.activityType === "dom_access") {
      if(activity.apiCall === "XMLHttpRequest.open") {
        var reqId = "A" + recordedData.activityId;
        var url = getActivityArgUrl(activity, 1);

        onWebResourceDetected(url, "XHR");
      }
    }
  },
  network_event_handler: function(perm, req) {
    onWebResourceDetected(req.url, req.type);
  }
}

PERMISSIONS["<all_urls>"] = {
  manifest_loaded_handler: addPermissionManifestLoadedHandler
}


standardChromePermission("alarms");
standardChromePermission("bookmarks");
standardChromePermission("browsingData");
standardChromePermission("contentSettings");
standardChromePermission("contextMenus");
standardChromePermission("debugger");
standardChromePermission("downloads");
standardChromePermission("fileBrowserHandler");
standardChromePermission("fontSettings");
standardChromePermission("history");
standardChromePermission("identity");
standardChromePermission("idle");
standardChromePermission("notifications");
standardChromePermission("pageCapture");
standardChromePermission("power");
standardChromePermission("privacy");
standardChromePermission("proxy");
standardChromePermission("pushMessaging");
standardChromePermission("system.display");
standardChromePermission("system.storage");
standardChromePermission("tabCapture");
standardChromePermission("topSites");
standardChromePermission("tts");
standardChromePermission("ttsEngine");
standardChromePermission("webNavigation");
standardChromePermission("webRequest");



activityBasedPermission("management", function(perm, activity) {
  if(activity.activityType === "api_call") {
    var apiCall = activity.apiCall;
    if(/chrome\.management\./.exec(apiCall) !== null) {
      apiCall = apiCall.replace("chrome.management.", "");
      if(apiCall.indexOf("getPermissionWarningByManifest") !== 0 &&
         apiCall.indexOf("uninstallSelf") !== 0) {
        onPermissionDetected("management");
      }
    }
  }
});

activityBasedPermission("webRequestBlocking", function(perm, activity) {
  if(activity.activityType === "api_call") {
    var apiCall = activity.apiCall;

    if(apiCall === "webRequestInternal.addEventListener") {
      var args = JSON.parse(activity.args);
      var arg2 = args[2];
      if(arg2 instanceof Array) {
        for(var i in arg2) {
          if(arg2[i] === "blocking")
            onPermissionDetected("webRequestBlocking");
        }
      }
    }

    if(/chrome.\./.exec(apiCall) !== null) {
      apiCall = apiCall.replace("chrome.management.", "");
      if(apiCall.indexOf("getPermissionWarningByManifest") !== 0 &&
         apiCall.indexOf("uninstallSelf") !== 0) {
        onPermissionDetected("management");
      }
    }
  }
});

function clipboardAnswerHandler(perm, q_id, answer) {
  if(answer === "paste") {
    onPermissionDetected("clipboardRead");
    onPermissionUndetected("clipboardWrite");
  } else if(answer === "copy") {
    onPermissionDetected("clipboardWrite");
    onPermissionUndetected("clipboardRead");
  } else if(answer === "copypaste") {
    onPermissionDetected("clipboardWrite");
    onPermissionDetected("clipboardRead");
  } else if(answer === "neither") {
    onPermissionUndetected("clipboardWrite");
    onPermissionUndetected("clipboardRead");
  }
}

function yesActivates(perm, q_id, answer) {
  if(answer === "yes")
    onPermissionDetected(perm);
  else
    onPermissionUndetected(perm);
}

questionBasedPermission("clipboardRead", "clipboard", clipboardAnswerHandler);
questionBasedPermission("clipboardWrite", "clipboard", clipboardAnswerHandler);
questionBasedPermission("geolocation", "geolocation", yesActivates);
questionBasedPermission("unlimitedStorage", "unlimitedStorage", yesActivates);
questionBasedPermission("background", "background", yesActivates);

function makeQuestionPath(type) {
  return "resources/lint/questions/q_" + type + ".html";
}

var QUESTIONS = {
    'tabs': {
      src: makeQuestionPath("tabs"),
      triggers: ['tabs'],
    },
    'clipboard': {
      src: makeQuestionPath("clipboard"),
      triggers: ["clipboardRead", "clipboardWrite"]
    },
    'geolocation': {
      src: makeQuestionPath("geolocation"),
      triggers: ['geolocation'],
    },
    'unlimitedStorage': {
      src: makeQuestionPath("unlimitedstorage"),
      triggers: ['unlimitedStorage']
    },
    'background': {
      src: makeQuestionPath("background"),
      triggers: ['background']
    }
};

var QUESTION_TRIGGERS = function(questions) {
  var res = {};
  for(var q_id in QUESTIONS) {
    var q = QUESTIONS[q_id];
    for(var y in q.triggers) {
      var trigger = q.triggers[y];
      if(res[trigger] === undefined)
        res[trigger] = [];
      res[trigger].push(q_id);
    }
  }
  return res;
}(QUESTIONS);

$(function() {

  $("#error").hide();
  $("#close").click(function() {
    chrome.app.window.current().close();
  });
  fillInExtensions();
  $("#start_logging").click(startRecording);
  $("#stop_logging").click(stopRecording);

  selectExtension(window.location.hash.substring(1));
});

var watchedExtensionId = null;
var recordedData = null;

function htmlEscape(what) {
  return $("<div></div>").text(what).html();
}

function fillInExtensions() {
  chrome.management.getAll(function(exts) {
    for(var i in exts) {
      if(exts[i].id !== "gmijieoebjcfhgidflfpdgikodoibjad") {
        //continue;
      }
      var listItem = $("<li class='list-group-item'><a href='#'>" + exts[i].name +" (" + exts[i].id + ")</a></li>");

      $("#ext_list").append(listItem);
      // Make closure.
      listItem.find("a").click(
        function(id) {
          return function() {
            selectExtension(id);
          };
        }(exts[i].id)
      );
    }
  });
}

function fillExtensionInfo() {
  fillPermissions();
  fillWebResources();
}

function isHostPermission(perm) {
  if(perm.indexOf("://") !== -1)
    return true;
  if(perm === "<all_urls>")
    return true;

  return false;
}

function fillPermissions() {
  for(var i in recordedData.manifest.permissions) {
    var perm = recordedData.manifest.permissions[i];
    addPermission(perm);
  }
}

function onWebResourceDetected(url, type) {
  if(type === "XHR") {
    var hostPerm = extractPermHost(url);
    if(hostPerm.indexOf("chrome-extension://") !== 0)
      onPermissionDetected(hostPerm);

    var hostCSP = extractCSPHost(url);
    if(hostCSP.indexOf("chrome-extension://") !== 0)
      onCSPDetected(hostCSP, "connect");
    else
      onCSPDetected("self", "connect");
  } else {
    var hostCSP = extractCSPHost(url);
    if(hostCSP.indexOf("chrome-extension://") !== 0)
      onCSPDetected(hostCSP, "default");
    else
      onCSPDetected("self", "connect");

  }
}

function addPermission(name) {
  var newPerm = $("<tr><td>" + htmlEscape(name) + "</td><td><input type='checkbox' disabled perm='" + name + "'></td></tr>")
  $("#permissions table").append(newPerm);
  recordedData.shown_permissions[name] = true;
}

function addCSP(name, type) {
  var newCsp = $("<tr><td>" + htmlEscape(name) + "</td><td>" + type + "</td><td><input disabled type='checkbox' csp-val='" + name + "' csp-type='" + type + "'></td></tr>")
  $("#webresources table").append(newCsp);
  recordedData.shown_csp[mkCSPId(name, type)] = true;
}

function checkPermission(name) {
  $("#permissions").find("[perm='" + name + "']").prop('checked', true);
}

function uncheckPermission(name) {
  $("#permissions").find("[perm='" + name + "']").prop('checked', false);
}

function mkCSPId(name, type) {
  return name + " " + type;
}

function checkCSP(name, type) {
  $("#webresources").find("[csp-val='" + name + "'][csp-type='" + type + "']").prop('checked', true);
}

function uncheckCSP(name) {
  $("#webresources").find("[csp-val='" + name + "'][csp-type='" + type + "']").prop('checked', false);
}


function selectExtension(id) {
  watchedExtensionId = id;
  startRecording();
}

function getLocation(href) {
    var l = document.createElement("a");
    l.href = href;
    return l;
}

function extractCSPHost(url) {
  var loc = getLocation(url);
  var host = loc.protocol + '//' + loc.hostname;
  return host;
}

function extractPermHost(url) {
  return extractCSPHost(url) + "/*";
}

function getExtensionUrl(eId) {
  return "chrome-extension://" + eId + "/";
}

function onAttach(tabId) {
  if (chrome.runtime.lastError) {
    console.debug(chrome.runtime.lastError.message);
    return;
  }

  chrome.debugger.sendCommand({tabId:tabId}, "Network.enable");
  console.debug("attached " + tabId);
}

function onAttachExtension(eId) {
  if (chrome.runtime.lastError) {
    var msg = chrome.runtime.lastError.message;
    if(msg.indexOf("silent-debugger-extension-api") !== -1) {
      $("#error").html("Please go to chrome://flags and enable silent-debugger-extension-api. Then restart your browser and try again.").show();
    }
    console.debug(msg);
    return;
  }

  var debugeeId = {extensionId: eId};
  chrome.debugger.sendCommand(debugeeId, "Network.enable", function() {
    if(chrome.runtime.lastError)
      console.debug("Failed enabling network for extension: " + chrome.runtime.lastError.message);
    else
      console.debug("dbugger nbled");
  });
}

function attachDebugger(tab) {
  chrome.debugger.attach({tabId:tab.id}, "1.0",
        onAttach.bind(null, tab.id));
}

function attachDebuggerToExtension(eid) {
  chrome.debugger.attach({extensionId: eid}, "1.0",
        onAttachExtension.bind(null, eid));
}

function getApiFile() {
    return $.ajax({
        type: "GET",
        url: "/data/apis.json",
        async: false,
    }).responseText;
}

function loadApiPermissionMapping() {
  var apiMap = [];
  var data = getApiFile()
  var apiDef = null;
  eval("apiDef = (" + data + ");");
  for(var key in apiDef) {
    if(apiDef[key].dependencies !== undefined) {
      for(var i in apiDef[key].dependencies) {
        var dep = apiDef[key].dependencies[i];
        if(dep.indexOf("permission:") === 0) {
          apiMap.push([new RegExp(key + '\..*'), dep.replace("permission:", "")]);
        }
      }
    }
  }

  // Custom map.
  apiMap.push([new RegExp("tabs\..*"), "tabs"]);
  return apiMap;
}

function startRecording() {
  // Initialize datastructures to which we capture the data.
  recordedData = {};
  recordedData.activityId = 0;
  recordedData.network_req = {};
  recordedData.network_req_pairs = {};
  recordedData.api_calls = {};
  recordedData.manifest = null;
  recordedData.permissions = {};
  recordedData.attached_to = [];
  recordedData.questions = {};
  recordedData.shown_permissions = {};
  recordedData.shown_csp = {};

  // If user declared these permissions we need to ask him directly, because
  // we cannot detect if he uses them.
  //recordedData.uncheckablePermissions = ["clipboardRead", "clipboardWrite", "geolocation",
  //    "unlimitedStorage", "background"];


  // Start logging the activity of the extension.
  chrome.activityLogPrivate.onExtensionActivity.addListener(onActivity);

  // Attach debugger to the extension's background page.
  chrome.debugger.onEvent.addListener(onNetworkEvent);


  // Now we should also attach to all the tabs that the extension opened. But
  // since we are laso re-loading the extension, we don't need to do that, as
  // any new extension's tabs will be taken care of by the following
  // tabs.onCreated handler.

  // If a new tab is created belonging to the extension, attach debugger.
  chrome.tabs.onCreated.addListener(function(tab) {
    if(tab.url.indexOf(getExtensionUrl(watchedExtensionId)) === 0) {
      attachDebugger(tab);
      recordedData.attached_to.push(tab.id);
    }
  });

  // Reload the extension (disable -> enable).
  chrome.management.setEnabled(watchedExtensionId, false, function() {
    chrome.management.setEnabled(watchedExtensionId, true, function() {
      attachDebuggerToExtension(watchedExtensionId);
    });
  });

  // Load the manifest of the extension.
  $.get(getExtensionUrl(watchedExtensionId) + "manifest.json")
   .done(function(data) {
     recordedData.manifest = JSON.parse(data);
     onManifestLoaded();
    })
   .error(function(data) {
     recordedData.manifest = {};
   });
}

function stopRecording() {
  chrome.debugger.detach({extensionId: watchedExtensionId});
  for(var i in recordedData.attached_to) {
    chrome.debugger.detach({tabId: recordedData.attached_to[i]});
  }
}

function onNetworkEvent(tab, message, params) {
  if(message === "Network.responseReceived") {
      if(params.type !== "XHR") {  // XHRs are captured in onActivity
        var req = {
          url: params.response.url,
          type: params.type
        };
        triggerPermissionHandler("network_event_handler", [req]);
      }
  }
}

function triggerPermissionHandler(handler_name, arguments) {
  for(var perm in PERMISSIONS) {
    var obj = PERMISSIONS[perm];
    if(obj[handler_name]) {
      //console.debug(handler_name + " " + perm);

      obj[handler_name].apply(this, [perm].concat(arguments));
    }
  }
}

function onActivity(activity) {
  console.debug("here");
  console.debug(activity);
  if(activity.extensionId === watchedExtensionId) {
    triggerPermissionHandler("activity_handler", [activity]);
  }
}

function onQuestionAnswered(q_id) {
  triggerPermissionHandler("question_answered_handler", [q_id, recordedData.questions[q_id].value]);
}

function onManifestLoaded() {
  triggerPermissionHandler("manifest_loaded_handler", []);
}

function buildPermissions() {
  var perms = [];
  $("#permissions input").each(function(ndx, el) {
    var jel = $(el);
    if(jel.prop("checked") === true) {
      var perm = jel.attr("perm");
      perms.push(perm);
    }
  });
  return perms;
}

function buildCSP() {
  var csp = {};
  $("#webresources input").each(function(ndx, el) {
    var jel = $(el);
    if(jel.prop("checked") === true) {
      var cspVal = jel.attr("csp-val");
      var cspType = jel.attr("csp-type");
      var cspKey = cspType + "-src";
      if(csp[cspKey] === undefined) {
        csp[cspKey] = [];
      }
      if(cspVal === "self") {
        cspVal = "'self'"
      }
      csp[cspKey].push(cspVal);
    }
  });
  var res = "";
  for(var cspType in csp) {
    res += cspType;
    res += " ";
    res += csp[cspType].join(" ");
    res += "; ";
  }
  return res;
}

function updateManifest() {
  var newManifest = recordedData.manifest;
  newManifest["permissions"] = buildPermissions();
  newManifest["content_security_policy"] = buildCSP();

  $("#results").text(
    JSON.stringify(newManifest, undefined, 2)
  );
}

function addQuestion(q_id, reason) {
  var q = QUESTIONS[q_id];
  if(recordedData.questions[q_id] === undefined) {
    recordedData.questions[q_id] = {
      shown: true
    };

    var filename = q.src;
    $.get(filename)
     .done(function(data) {
        var newQ = $(data);
        if(reason !== undefined) {
          var questionMarkContent = reason(q);
          var questionMark = $('<div class="btn"><span class="glyphicon clickable glyphicon-question-sign"></span></div>');
          /*questionMark.popover({
                html: true,
                content: questionMarkContent,
                trigger: 'hover',
                title: 'Explanation',
                placement: 'bottom',
              });*/
          newQ.find('.btn-group').append(questionMark);
        }

        $("#questions").prepend(newQ);
        newQ.find("button").each(function(ndx, btn) {
          $(btn).click(function() {
            recordedData.questions[q_id].value = $(btn).attr("q-answer");
            $(btn).siblings("button").removeClass("selected");
            newQ.addClass("done");
            $(btn).addClass("selected");
            onQuestionAnswered(q_id);
          });
        })

     });
   }
}

function onPermissionUndetected(perm, how) {
  uncheckPermission(perm);
  updateManifest();
}

function onPermissionDetected(perm, how) {
  if(recordedData.shown_permissions[perm] === undefined)
    addPermission(perm);
  checkPermission(perm);
  updateManifest();
}

function onCSPDetected(perm, type) {
  if(recordedData.shown_csp[mkCSPId(perm, type)] === undefined)
    addCSP(perm, type);
  checkCSP(perm, type);
  updateManifest();
}

function onCSPUndetected(perm, type) {
  uncheckCSP(perm, type);
  updateManifest();
}
