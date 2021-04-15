function showLog(log) {
  if (!log) { return; }
  let curLog = $("#logDiv").html().split("<br>");
  curLog = curLog.concat(log);
  if (curLog.length > 200) {
    curLog = curLog.slice(100);
  }
  $("#logDiv").html(curLog.join("<br>"));
  $("#logDiv").animate({"scrollTop": $("#logDiv")[0].scrollHeight});
  $("#modalLogDiv").html($("#logDiv").html());
  $("#modalLogDiv").animate({"scrollTop": $("#modalLogDiv")[0].scrollHeight});
}

function execute() {
  let address = $("#dropdownDisasToggle").text().split(":")[0];
  let seed = $("#dropdownSeedToggle").text();
  let context = $("#inputCtx").val();
  let requestData = {"address": address, "context": context, "seed": seed};
  if ($("#nav-tab").attr("select") == "CPUState") {
    // display loading block
    $("#nav-cpustate .context-loading").removeClass("d-none");
    // call CPUState API
    $.getJSON("/cpustate", requestData);
  } else if ($("#nav-tab").attr("select") == "Relationship") {
    // display loading block
    $("#nav-relation .context-loading").removeClass("d-none");
    // call relationship API
    $.getJSON("/relationship", requestData);
  } else if ($("#nav-tab").attr("select") == "FuncCov") {
    // display loading block
    $("#nav-funccov .context-loading").removeClass("d-none");
    $.getJSON("/funccov", requestData, function (data) {
      $("#nav-funccov .context-loading").addClass("d-none");
      // return [hit, total, lonely, addr]
      // show FuncCov
      $("#divFuncCov").html(data["cov"].map(function (stats) {
	return stats2link(stats[0], stats[1], stats[3]);
      }));
      // show FuzzerDiff
      $("#divFuzzerDiff").html(data["fuzzer_diff"].map(function (stats) {
	return stats2link(stats[2], stats[0], stats[3]);
      }));
    });
  }
}

function stats2link(a, b, addr) {
  let result = addr;
  result += " " + a + "/" + b;
  result = "<a href=\"" + "/?address=" + addr + "\">" + result;
  result += "</a><br>";
  return result;
}

function prepareConstraint() {
  let pid = 0;
  let ctx = $("#inputConstraint").val();
  pid = $("#dropdownCurFuzzerToggle").text();
  pid = pid.split("[").map(function (x) {
    return parseInt(x);
  }).filter(function (x) {
    return !!x;
  })[0];
  $.getJSON("/constraint", {"context": ctx, "pid": pid});
  $("#btnConstraint").text("...");
  setTimeout(function () { $("#btnConstraint").text("Constraint"); }, 1000);
}

function hitboxAnimate(nodes, network) {
  nodes.map(function (node) {
    let address = parseInt(node["id"]);
    let pos = network.getPosition(node["id"]);
    pos.y -= 60;
    pos = network.canvasToDOM(pos);
    $("#" + node["id"]).animate({left: pos.x, top: pos.y});
  });
}

function drawPath(seed) {
  let blocks = nodes.map(function (i){return i['id']}).join('_');
  $.post("/path/get", {"blocks": blocks, "seed": seed}, function(data, status){
    $("#hitCntDiv div").removeClass("cur-path");
    data["path"].map(function(x) {
      $("#" + x).addClass("cur-path");
    });
  });
}

function showBitmap(data, nodes, network, defaultSeed) {
  if (!data) { return; }
  // update hitbox
  addrs = data["addrs"];
  colors = {};
  nodes.map(function (node) {
    let address = parseInt(node["id"]);
    let stat = addrs["0x" + address.toString(16)];
    let hit = "";
    // setup different color for fuzzer
    if (Object.keys(colors).length == 0) {
      // 1: rgb[0] + 128, -1: rgb[0] - 128
      actions = [1, -3, 2, -1, 3, -2];
      actIdx = 0;
      rgb = [0, 0, 192];
      fuzzerColorHtml = "";
      for (pid in stat["fuzzers"]) {
	// setup colors
	key = stat["fuzzers"][pid] + "[" + pid + "]";
	colors[key] = rgb.slice();
	// prepare fuzzerColorHtml
	fuzzerColorHtml += "<font style=\"color: ";
	fuzzerColorHtml += "rgb(" + colors[key].join(",") + ");\">";
	fuzzerColorHtml += key;
	fuzzerColorHtml += " ★</font><br>";
	// calc next color
	act = actions[actIdx];
	idx = Math.abs(act) - 1;
	rgb[idx] += (act > 0)? 192 : -192;
	actIdx = (actIdx + 1) % actions.length;
      }
      $("#fuzzerColorDiv").html(fuzzerColorHtml);
    }
    // append circle to different fuzzer
    for (pid in stat["fuzzers"]) {
      key = stat["fuzzers"][pid] + "[" + pid + "]";
      hit += "<font style=\"color: " + "rgb(" + colors[key].join(",") + ");";
      hit += "font-size: 24px;\">";
      hit += "★</font>";
    }
    // TODO: display stat["hit"] when mouse hover
    $("#" + node["id"]).html(hit);
  });
  // update seeds dropdown
  seeds = data["seeds"];
  initDropdown("dropdownCurSeed", seeds, function (x) {
    return x;
  }, defaultSeed, drawPath);
  // update fuzzer dropdown
  defaultFuzzer = $("#dropdownCurFuzzerToggle").text();
  fuzzers = Object.keys(colors);
  initDropdown("dropdownCurFuzzer", fuzzers, function (x) {
    return x;
  }, defaultFuzzer, function (x) {});
}

function seed2hexdump(seed) {
  let ind = 0;
  let bytesInd = 0;
  let printableInd = 0;
  let offset = [];
  let bytes = [];
  let printable = [];
  while (seed.length) {
    offset.push(ind.toString(16).padStart(8, "0"));
    // setup bytes
    bytes.push(seed.slice(0, 16).map(function (c) {
      let data = c.toString(16).padStart(2, "0");
      data = "<div class=\"div-hex\" id=\"divHexBytes" + bytesInd + "\">" + data + "</div>";
      bytesInd += 1;
      return data;
    }).join(" "));
    // setup printable
    printable.push(seed.slice(0, 16).map(function (c) {
      let data = (c >= 32 && c <= 126) ? String.fromCharCode(c) : ".";
      data = "<div class=\"div-hex\" id=\"divHexPrintable" + printableInd + "\">" + data + "</div>";
      printableInd += 1;
      return data;
    }).join(""));
    ind += 16;
    seed = seed.slice(16)
  }
  $("#divHexOffset").html(offset.join("<br>"));
  $("#divHexBytes").html(bytes.join("<br>"));
  $("#divHexPrintable").html(printable.join("<br>"));
}

let initMutable;
let initUnmtable;

function showRelationship(data) {
  if (data) {
    data.map(function (ctx) {
      if (ctx["action"] == "input") {
	// init
	$("#divExpect").html("");
	initMutable = 0;
	initUnmutable = 0;
	// seed
	seed2hexdump(ctx["data"]);
      } else if (ctx["action"] == "unmutable") {
	if (initUnmutable == 0) {
	  initUnmutable = 1;
	  $("#divHexBytes div").addClass("unmutable");
	  $("#divHexPrintable div").addClass("unmutable");
	}
	for (i = ctx["data"][0]; i < ctx["data"][1]; i++) {
	  $("#divHexBytes" + i).removeClass("unmutable");
	  $("#divHexPrintable" + i).removeClass("unmutable");
	}
      } else if (ctx["action"] == "mutable") {
	if (initMutable == 0) {
	  initMutable = 1;
	  $("#divHexBytes div").not(".unmutable").addClass("mutable");
	  $("#divHexPrintable div").not(".unmutable").addClass("mutable");
	}
	for (i = ctx["data"][0]; i < ctx["data"][1]; i++) {
	  $("#divHexBytes" + i).removeClass("mutable");
	  $("#divHexPrintable" + i).removeClass("mutable");
	}
      } else if (ctx["action"] == "expect") {
	$("#divExpect").html(ctx["data"]);
	$("#nav-relation .context-loading").addClass("d-none");
      }
    });
  }
}

function showCPUState(data) {
  if (data) {
    $("#nav-cpustate .context-loading").addClass("d-none");
    $("#divCPUState").html(data);
  }
}

function DOT2CFG(DOTstring, addrFix) {
  var parsedData = vis.parseDOTNetwork(DOTstring);

  var data = {
    nodes: parsedData.nodes,
    edges: parsedData.edges
  }

  //var options = parsedData.options;
  const options = {
    layout: {
      hierarchical: {
	enabled: true,
	levelSeparation: 150,
      },
    },
    physics: {
      hierarchicalRepulsion: {
	nodeDistance: 150,
      },
    },
  };

  // fix edge address
  data.edges.map(function (edge) {
    edge.from = "0x" + (parseInt(edge.from) + addrFix).toString(16);
    edge.to = "0x" + (parseInt(edge.to) + addrFix).toString(16);
  });

  var level = {}
  if (data.edges.length)
    level[data.edges[0].from] = 0;
  var last_level = 0;
  for (i in data.edges) {
    edge = data.edges[i];
    if (!(edge.to in level)) {
      if (!(edge.from in level)) {
	level[edge.from] = last_level;
      }
      level[edge.to] = level[edge.from] + 1;
      last_level = level[edge.to];
    }
  }

  for (i in data.nodes) {
    node = data.nodes[i];
    // fix node address
    node.id = "0x" + (parseInt(node.id) + addrFix).toString(16);
    // set layout
    node.color = {
      border: "#000000",
      background: "#FFFFFF",
      highlight: {
	border: "#28a745",
	background: "#FFFFFF",
      },
    };
    node.font = { face: "monospace", align: "left" };
    node.level = level[node.id];
    node.label = node.id;
  }

  // create a network
  var container = document.getElementById("mynetwork");
  var network = new vis.Network(container, data, options);

  network.on("click", function (data) {
    if (data.nodes.length !== 0) {
      var address = data.nodes[0];
      // show modal
      $("#visualContent").modal("show");
      $("#visualContent").on("shown.bs.modal", function (e) {
	// scroll log to bottom
	$("#modalLogDiv").animate({"scrollTop": $("#modalLogDiv")[0].scrollHeight});
      });
      $("#visualContentLongTitle").text("Address: " + address);
      // prepare disassembly
      $.getJSON("/basicblock/disassemble", {"address": address}).done(function(data, status){
	// init disassembly dropdown
	initDropdown("dropdownDisas", data["disasm"], function (x) {
	  var result = "";
	  result += "0x" + x["offset"].toString(16);
	  result += ":\t" + x["opcode"];
	  return result;
	}, "none", function (x) {});
	// init seed dropdown
	initDropdown("dropdownSeed", data["seeds"], function (x) {
	  return x;
	}, "none", function (x) {});
      });
    }
  });

  // create hit counter box
  $("#hitCntDiv").html(data.nodes.map(function (node) {
    var result = '<div id="' + node.id + '" class="hit-box"></div>';
    return result;
  }).join(''));

  // switch between CPUState and Relationship
  $("#nav-tab a").click(function () {
    $("#nav-tab").attr("select", $(this).text());
  });

  return [network, data];
}

function initDropdown(id, data, format, activeItem, clickFunc) {
  // map to items
  $("#" + id + "Menu").html(data.map(function (x) {
    var result = format(x);
    var item = '<a class="dropdown-item" href="#">' + result + '</a>';
    return item;
  }).join(""));
  // set first or default
  let defaultItem = $("#" + id + "Menu a:contains('" + activeItem + "')");
  if (defaultItem.length == 0) {
    defaultItem = $($("#" + id + "Menu a")[0]);
  } else {
    defaultItem = $(defaultItem[0]);
  }
  $("#" + id + "Toggle").text(defaultItem.text());
  $("#" + id + "Toggle").val(defaultItem.text());
  defaultItem.addClass("active");
  clickFunc(defaultItem.text());
  // regist click event
  $("#" + id + "Menu a").click(function(){
    $("#" + id + "Toggle").text($(this).text());
    $("#" + id + "Toggle").val($(this).text());
    $("#" + id + "Menu a").removeClass("active");
    $(this).addClass("active");
    clickFunc($(this).text());
  });
}
