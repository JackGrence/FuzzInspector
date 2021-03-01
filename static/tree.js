function prepareConstraint() {
  ctx = $("#constraintCtx").val();
  $.getJSON("/constraint", {"context": ctx});
}

function showBitmap(data) {
  for (var addr in data) {
    try {
      document.getElementById(addr).innerHTML = addr + " [" + data[addr]["hit"] + "]";
    } catch (e) {
    }
  }
}

function prepareRelationship() {
  loading = '<div class="spinner-border" role="status"><span class="sr-only">Loading...</span></div>';
  $("#relationship").html($("#relationship").html() + loading);
  addr = $("#relationAddr").val();
  ctx = $("#relationCtx").val();
  $.getJSON("/relationship", {"address": addr, "context": ctx});
}

function showRelationship(data) {
  if (data !== '')
    $("#relationship").html(data);
}

function prepareCPUState() {
  address = this.textContent;
  $("#relationAddr").val(address);
  $("#loading").html('<div class="spinner-border" role="status"><span class="sr-only">Loading...</span></div>');
  $.getJSON("/cpustate", {"address": address, "context": $("#userCtx").val()});
}

function showCPUState(data) {
  if (data !== '') {
    $("#cpustate").html(data);
    $("#loading").html('');
  }
}

function showAssembly(e) {
  address = e.data.name;
	/*
<div class="input-group mb-3">
  <div class="input-group-prepend">
    <button class="btn btn-outline-secondary" type="button">Button</button>
  </div>
  <input type="text" class="form-control" placeholder="" aria-label="" aria-describedby="basic-addon1">
</div>
	 */
  $.getJSON("/basicblock/disassemble", {"address": address}).done(function(data, status){
    $("#disasm").html('');
    $(data).each(function() {
      var group = $("<div>").prop("class", "input-group");
      var addrBtn = $("<div>").prop("class", "input-group-prepend")
		    .append($("<button>").prop("class", "btn btn-outline-secondary")
		    .prop("type", "button").text("0x" + this["offset"].toString(16)))
		    .click(prepareCPUState);
      var asmText = $("<input>").prop("type", "text").prop("class", "form-control")
		    .prop("aria-describedby", "basic-addon1")
		    .prop("value", this["opcode"]);
      $("#disasm").append(group.append(addrBtn).append(asmText));
    });
  });
}

function redraw() {
  // Assigns parent, children, height, depth
  root = d3.hierarchy(treeData, function(d) { return d.children; });
  root.x0 = height / 2;
  root.y0 = 0;

  // Collapse after the second level
  // root.children.forEach(collapse);

  update(root);
}

// Collapse the node and all it's children
function collapse(d) {
  if(d.children) {
    d._children = d.children
    d._children.forEach(collapse)
    d.children = null
  }
}

function update(source) {

  // Assigns the x and y position for the nodes
  var treeData = treemap(root);

  // Compute the new tree layout.
  var nodes = treeData.descendants(),
      links = treeData.descendants().slice(1);

  // Normalize for fixed-depth.
  nodes.forEach(function(d){ d.y = d.depth * 180});

  // ****************** Nodes section ***************************

  // Update the nodes...
  var node = svg.selectAll('g.node')
      .data(nodes, function(d) {return d.id || (d.id = ++i); });

  // Enter any new modes at the parent's previous position.
  var nodeEnter = node.enter().append('g')
      .attr('class', 'node')
      .attr("transform", function(d) {
        return "translate(" + source.y0 + "," + source.x0 + ")";
    })
    .on('click', showAssembly);

  // Add Circle for the nodes
  nodeEnter.append('circle')
      .attr('class', 'node')
      .attr('r', 1e-6)
      .style("fill", function(d) {
          return d._children ? "lightsteelblue" : "#fff";
      });

  // Add labels for the nodes
  nodeEnter.append('text')
      .attr("id", function(d) { return d.data.name; })
      .attr("dy", ".35em")
      .attr("x", function(d) {
          return d.children || d._children ? -13 : 13;
      })
      .attr("text-anchor", function(d) {
          return d.children || d._children ? "end" : "start";
      })
      .text(function(d) { return d.data.name; });

  // UPDATE
  var nodeUpdate = nodeEnter.merge(node);

  // Transition to the proper position for the node
  nodeUpdate.transition()
    .duration(duration)
    .attr("transform", function(d) {
        return "translate(" + d.y + "," + d.x + ")";
     });

  // Update the node attributes and style
  nodeUpdate.select('circle.node')
    .attr('r', 10)
    .style("fill", function(d) {
        return d._children ? "lightsteelblue" : "#fff";
    })
    .attr('cursor', 'pointer');


  // Remove any exiting nodes
  var nodeExit = node.exit().transition()
      .duration(duration)
      .attr("transform", function(d) {
          return "translate(" + source.y + "," + source.x + ")";
      })
      .remove();

  // On exit reduce the node circles size to 0
  nodeExit.select('circle')
    .attr('r', 1e-6);

  // On exit reduce the opacity of text labels
  nodeExit.select('text')
    .style('fill-opacity', 1e-6);

  // ****************** links section ***************************

  // Update the links...
  var link = svg.selectAll('path.link')
      .data(links, function(d) { return d.id; });

  // Enter any new links at the parent's previous position.
  var linkEnter = link.enter().insert('path', "g")
      .attr("class", "link")
      .attr('d', function(d){
        var o = {x: source.x0, y: source.y0}
        return diagonal(o, o)
      });

  // UPDATE
  var linkUpdate = linkEnter.merge(link);

  // Transition back to the parent element position
  linkUpdate.transition()
      .duration(duration)
      .attr('d', function(d){ return diagonal(d, d.parent) });

  // Remove any exiting links
  var linkExit = link.exit().transition()
      .duration(duration)
      .attr('d', function(d) {
        var o = {x: source.x, y: source.y}
        return diagonal(o, o)
      })
      .remove();

  // Store the old positions for transition.
  nodes.forEach(function(d){
    d.x0 = d.x;
    d.y0 = d.y;
  });

  // Creates a curved (diagonal) path from parent to the child nodes
  function diagonal(s, d) {

    path = `M ${s.y} ${s.x}
            C ${(s.y + d.y) / 2} ${s.x},
              ${(s.y + d.y) / 2} ${d.x},
              ${d.y} ${d.x}`

    return path
  }

  // Toggle children on click.
  function click(d) {
    if (d.children) {
        d._children = d.children;
        d.children = null;
      } else {
        d.children = d._children;
        d._children = null;
      }
    update(d);
  }
}

function DOT2CFG(DOTstring) {
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

  // you can extend the options like a normal JSON variable:

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
	data = data.map(function (x) {
	  var result = "";
	  result += "0x" + x["offset"].toString(16);
	  result += ":\t" + x["opcode"];
	  var item = '<a class="dropdown-item" href="#">' + result + '</a>';
	  return item;
	}).join("");
	$("#dropdownDisasMenu").html(data);
	// regist click event
	$(".dropdown div a").click(function(){
	  console.log(this);
	  $("#dropdownDisasToggle").text($(this).text());
	  $("#dropdownDisasToggle").val($(this).text());
	  $(".dropdown div a").removeClass("active");
	  $(this).addClass("active");
	});
      });
    }
  });

  return [network, data];
}
