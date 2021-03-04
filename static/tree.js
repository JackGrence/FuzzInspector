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
  } else {
    // display loading block
    $("#nav-relation .context-loading").removeClass("d-none");
    // call relationship API
    $.getJSON("/relationship", requestData);
  }
}

function prepareConstraint() {
  ctx = $("#inputConstraint").val();
  $.getJSON("/constraint", {"context": ctx});
  $("#btnConstraint").text("...");
  setTimeout(function () { $("#btnConstraint").text("Constraint"); }, 1000);
}

function showBitmap(data, nodes, network) {
  nodes.map(function (node) {
    let address = parseInt(node["id"]);
    let hit = data["0x" + address.toString(16)]["hit"];
    let pos = network.getPosition(node["id"]);
    pos.y -= 60;
    pos = network.canvasToDOM(pos);
    $("#" + node["id"]).css({left: pos.x, top: pos.y});
    $("#" + node["id"]).text("[" + hit + "]");
  });
}

function showRelationship(data) {
  if (data !== '') {
    $("#nav-relation .context-loading").addClass("d-none");
    $("#divRelation").html(data);
  }
}

function showCPUState(data) {
  if (data !== '') {
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
      $("#visualContentLongTitle").text("Address: " + address);
      // prepare disassembly
      $.getJSON("/basicblock/disassemble", {"address": address}).done(function(data, status){
	// map disassembly to items
	disasm = data["disasm"];
	$("#dropdownDisasMenu").html(disasm.map(function (x) {
	  var result = "";
	  result += "0x" + x["offset"].toString(16);
	  result += ":\t" + x["opcode"];
	  var item = '<a class="dropdown-item" href="#">' + result + '</a>';
	  return item;
	}).join(""));
	// set first
	let first = "0x" + disasm[0]["offset"].toString(16);
	first += ":\t" + disasm[0]["opcode"];
	$("#dropdownDisasToggle").text(first);
	$("#dropdownDisasToggle").val(first);
	$($("#dropdownDisasMenu a")[0]).addClass("active");
	// regist click event
	$("#dropdownDisasMenu a").click(function(){
	  $("#dropdownDisasToggle").text($(this).text());
	  $("#dropdownDisasToggle").val($(this).text());
	  $("#dropdownDisasMenu a").removeClass("active");
	  $(this).addClass("active");
	});
	// map seeds to items
	seeds = data["seeds"];
	$("#dropdownSeedMenu").html(seeds.map(function (x) {
	  var result = x;
	  var item = '<a class="dropdown-item" href="#">' + result + '</a>';
	  return item;
	}).join(""));
	// set first
	first = seeds[0];
	$("#dropdownSeedToggle").text(first);
	$("#dropdownSeedToggle").val(first);
	$($("#dropdownSeedMenu a")[0]).addClass("active");
	// regist click event
	$("#dropdownSeedMenu a").click(function(){
	  $("#dropdownSeedToggle").text($(this).text());
	  $("#dropdownSeedToggle").val($(this).text());
	  $("#dropdownSeedMenu a").removeClass("active");
	  $(this).addClass("active");
	});
      });
    }
  });

  network.on("dragStart", function (data) {
    $("#hitCntDiv div").addClass("d-none");
  });

  network.on("dragEnd", function (data) {
    $("#hitCntDiv div").removeClass("d-none");
  });

  // create hit counter box
  $("#hitCntDiv").html(data.nodes.map(function (node) {
    var result = '<div id="' + node.id + '" class="hit-box">0</div>';
    return result;
  }).join(''));

  // switch between CPUState and Relationship
  $("#nav-tab a").click(function () {
    $("#nav-tab").attr("select", $(this).text());
  });

  return [network, data];
}
