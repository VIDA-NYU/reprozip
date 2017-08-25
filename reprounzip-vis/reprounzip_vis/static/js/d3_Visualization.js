/*-- Functions for d3 visualization  --*/


let DELAY = 200, clicks = 0, timer = null;

//-- Click any empty space within the svg body to reset the location for the packages and detached the links between the packages and processes
d3.select("body").on("click",function(){

    clicks++;

    if(clicks ===1){

        timer = setTimeout(function() {

            clicks = 0;

        }, DELAY);


    } else {

        clearTimeout(timer);

        if (d3.event.target.toString().includes("SVGSVGElement")) {

            console.log('clicked an empty space!');

            resetPackagesPosition();

        };

        clicks = 0;

    };





});




// update Tree function
function update(source) {




    // Compute the new tree layout.
    let nodes = tree.nodes(root).reverse(),
        links = tree.links(nodes);

    console.log('source.x: ', source.x);
    console.log('source.y: ', source.y);


    // Normalize for fixed-depth.
    nodes.forEach(function(d) { d.y = d.depth * 400;

    });



    // Update the nodes…
    let node = svg.selectAll("g.node")
        .data(nodes, function(d) { return d.id || (d.id = ++nodeId_Index);});




    let DELAY = 200, clicks = 0, timer = null;

    // Enter any new nodes at the parent's previous position.
    let nodeEnter = node.enter().append("g")
        .attr("class", "node")
        .attr("transform", function(d) { return "translate(" + source.y0 + "," + source.x0 + ")"; })
        //.on("dblclick", dblclickProcess)
        .on("click",

            function(d){

                //clickProcess

                clicks++;  //count clicks

                if(clicks === 1) {

                    timer = setTimeout(function() {

                        clickProcess(d);  //perform single-click action
                        clicks = 0;             //after action performed, reset counter

                    }, DELAY);

                } else {

                    clearTimeout(timer);    //prevent single-click action
                    dblclickProcess(d); //perform double-click action
                    clicks = 0;             //after action performed, reset counter
                };



            }

        )
        .on("mousedown", function(d){

            //  d3.select("body").transition().style("background-color", "#1c1c1c");



            // auto-show item content when show results reduces to single

            //                ;( function( $, window, document, undefined )
            //                {
            //                    let $container = $( '.viz' );
            //
            //
            //                    if( !$container.length ) return true;
            //
            //                    let $packages = $container.find( '.package' ),
            //                        $package			= $();
            //
            //                    $input.on( 'keyup', function()
            //                    {
            //                        $item = $items.not( '.is-hidden' );
            //                        if( $item.length === 1 )
            //                            $item.addClass( 'js--autoshown is-active' );
            //                        else
            //                            $items.filter( '.js--autoshown' ).removeClass( 'js--autoshown is-active' );
            //                    });
            //                })( jQuery, window, document );

        })
        .on("mouseup", function(d){

            console.log("mouseUP");
            d3.select("body").transition().style("background-color", "white");

        })
        .on("mouseover", function(d) {

            tooltip.transition()
                .duration(200)
                .style("opacity", .8);
            tooltip .html(
                d.description
            )
                .style("left", (d3.event.pageX) + "px")
                .style("top", (d3.event.pageY - 38) + "px");
        })
        .on("mouseout", function(d) {
            tooltip.transition()
                .duration(500)
                .style("opacity", 0);
        });




    nodeEnter.append("circle")
        .attr("r", 1e-6)
        .attr("class", "process")
        .attr("id",  function(d) { return "process_" + d.name.replace(/[ ()]/g,''); })
        .style("fill", function(d) { return d._children ? "lightsteelblue" : "#fff"; });

    nodeEnter.append("text")
        .attr("class", "processLabel")
        .attr("id",  function(d) { return "processLabel_" + d.name.replace(/[ ()]/g,''); })
        .attr("x", function(d) { return d.children || d._children ? -10 : 10; })
        .attr("dy", ".35em")
        .attr("text-anchor", function(d) { return d.children || d._children ? "end" : "start"; })
        .text(function(d) { return d.name; })
        .style("fill-opacity", 1e-6);



    // Transition nodes to their new position.
    let nodeUpdate = node.transition()
        .duration(duration)
        .attr("transform", function(d) {



            return "translate(" + d.y + "," + d.x + ")"; });

    nodeUpdate.select("circle")
        .attr("r", 8)
        .style("fill", function(d) { return d._children ? "lightsteelblue" : "#fff"; });

    nodeUpdate.select("text")
        .style("fill-opacity", 1);



    // Transition exiting nodes to the parent's new position.
    let nodeExit = node.exit().transition()
        .duration(duration)
        .attr("transform", function(d) { return "translate(" + source.y + "," + source.x + ")"; })
        .remove();


    nodeExit.select("circle")
        .attr("r", 1e-6);

    nodeExit.select("text")
        .style("fill-opacity", 1e-6);

    // Update the links…
    let link = svg.selectAll("path.link")
        .data(links, function(d) { return d.target.id; });

    // Enter any new links at the parent's previous position.
    link.enter().insert("path", "g")
        .attr("class", "link")
        .attr("d", function(d) {
            let o = {x: source.x0, y: source.y0};
            return diagonal({source: o, target: o});
        });


    // Transition links to their new position.
    link.transition()
        .duration(duration)
        .attr("d", diagonal);


    // Transition exiting nodes to the parent's new position.
    link.exit().transition()
        .duration(duration)
        .attr("d", function(d) {
            let o = {x: source.x, y: source.y};
            return diagonal({source: o, target: o});
        })
        .remove();


    // Update the link text
    let linktext = svg.selectAll("g.link")
        .data(links, function (d) {
            return d.target.id;
        });



    linktext.enter()
        .insert("g")
        .attr("class", "link")
        .attr("transform", function(d) { return "translate(" + d.source.y + "," + d.source.x + ")"; })
        .append("text")
        .attr("dy", ".35em")
        .attr("text-anchor", "middle")
        .style("font-size", 15)
        .text(function (d) {
            return d.target.rule;
        });

    // Transition link text to their new positions

    linktext.transition()
        .duration(duration)
        .attr("transform", function (d) {
            return "translate(" + ((d.source.y + d.target.y) / 2) + "," + ((d.source.x + d.target.x) / 2) + ")";
        })



    //Transition exiting link text to the parent's new position.
    linktext.exit().transition()
        .remove();





    // Stash the old positions for transition.
    nodes.forEach(function(d) {
        d.x0 = d.x;
        d.y0 = d.y ;

    });



    currentDisplayingNodes = nodes;
    console.log("currentDisplayingNodes: ", currentDisplayingNodes);



   // svg.append('use').attr('xlink:href','#package');


};

// Toggle children on click.
function dblclickProcess(d) {



    let links = force.links();

    links = [];

    edge = svg.selectAll(".edge").data(links);

    //Empty edges.
    edge.exit().remove();
    svg.selectAll("circle");


    forceLinks = links;

    force.links(links);

    restart();

    let isOpen = false;

    let newTimelineDuration;

    if (d.children) {


        d._children = d.children;
        d.children = null;

        decreaseTimeLineLen(d.y );

        console.log('Close');

        newTimelineDuration = (d.start_time - rootStartTime) / 1000000;


    } else {


        d.children = d._children;
        d._children = null;

        console.log('Open');

        isOpen = true;

        newTimelineDuration = (d.exit_time - rootStartTime) / 1000000;

        // let tempDuration = 0;
        //
        //
        // if (d.children != null){
        //
        //     d.children.forEach(function(node) {
        //
        //         if ((node.start_time - rootStartTime) > tempDuration) {
        //
        //             tempDuration = node.start_time - rootStartTime;
        //         };
        //
        //
        //     });
        // }
        // else{
        //     tempDuration = d.exit_time - rootStartTime;
        //
        // }
        //
        //
        // newTimelineDuration = tempDuration / 1000000;  //d.children[0].start_time - rootStartTime;


    }

    timeLineLen =  timeLineLen_Total * (newTimelineDuration / duration_total_ms);

    console.log('timeLineLen:', timeLineLen);

    //  let durationLabel  = "Took " + (duration / 1000000).toFixed(2) + " milliseconds";

    if(newTimelineDuration > 0 && isOpen == true){

    updateTimeLine(timeLineLen, getTimeLineLabel(newTimelineDuration,'took') + d.name + " is done.");
    }

    else if(newTimelineDuration > 0 && isOpen == false){

        updateTimeLine(timeLineLen , getTimeLineLabel(newTimelineDuration,'took') + d.name + " is started.");
    }
    else if(newTimelineDuration === 0){



        updateTimeLine(timeLineLen ,  d.name + " is the initial process");

    }
    else {

        updateTimeLine(0);

    }

    console.log('tree.size(): ',tree.size());
    console.log('timeLineLen_Total: ', timeLineLen_Total);


    update(d);

    updatedProcessDetails(d);


}


// Toggle tree  on click.
function clickProcess(d) {


    console.log('single click');

    console.log('This D: ', d);

    console.log('This this: ', this);


    let otherSVG = d3.selectAll(".process, .processLabel, .package, .edge, .packageLabel, .link");

    if(inFocus === true){


        otherSVG.style("opacity", 0.3);

    }
    else    otherSVG.style("opacity", 1);


    currentSelectedNode = d;



    if (thisNodeCircle != null && thisNodeCircleLabel != null){


        thisNodeCircle.transition().attr("r", 8);
        thisNodeCircleLabel.transition().style("font", "15px sans-serif").attr("x", function(d) { return d.children || d._children ? -10 : 10; });


    }



    thisNodeCircle = d3.select("#process_"+ d.name.replace(/[ ()]/g,''));  // d3.select("id","#process_" + d.name.replace(/[ ()]/g,''));
    thisNodeCircleLabel = d3.select("#processLabel_"+ d.name.replace(/[ ()]/g,''));  // d3.select("id","#process_" + d.name.replace(/[ ()]/g,''));


    thisNodeCircle.transition().attr("r", 20).style("opacity", 1);
    thisNodeCircleLabel
        .transition()
        .style("font", "20px sans-serif")
        .style("opacity", 1)
        .attr("x", function(d) { return d.children || d._children ? -30 : 30; });



    let links = force.links();

    links = [];

    edge = svg.selectAll(".edge").data(links);


    let edgeExit = edge.exit().remove();

    if(forceNodes.length > packagesNumber){

        forceNodes.pop();

    }

    // add links to any nearby nodes

    let node = {};
    node.x = d.y;
    node.y = d.x;
    node.px = d.y;
    node.py = d.x;
    node.weight = 10;
    node.radius = 20;
    node.fixed = true;



    let thisNode  = forceNodes.push(node);


    let circles = svg.selectAll("circle");



    forceNodes.forEach(function(target) {

        d.packages.reads.forEach(function (readFile) {

            if(target.name === readFile){



                d3.select(".package_" + readFile.replace(/[.,\/#!$%&;:+{}=\-_`~()]/g,"")).style("opacity", 1);
                d3.select("#packageLabel_" + readFile.replace(/[.,\/#!$%&;:+{}=\-_`~()]/g,"")).style("opacity", 1);

                links.push({source: node, target: target});

            }

        })



    });



    forceLinks = links;


    let label = svg.selectAll(".forceLabel")
        .data(force.nodes());

    label.attr("x", function(d){ return d.x; })
        .attr("y", function (d) {return d.y - 30; });

    force.links(links);
    //force.nodes(thisNode);



    restart();

    updatedProcessDetails(d);




}

function updatedProcessDetails(d){



    // Delete the current processDetails section to prepare
    // for new information.

    processDetails.selectAll('*').remove();



    // Extract and prepare the commands message for this selected process
    let commands = '';

    if(d.argv != null){

        d.argv.forEach(function(argv){

            commands += argv;//.concat(argv.toString());
            commands += ' ';

        });
    }
    else{

        commands = 'No argument for this process'
    }


    let runtime = ''; //new moment.duration((d.exit_time/1000000) - (d.start_time / 1000000));

    // runtime = runtime.asMilliseconds().toFixed(2) + " milliseconds";

    if (d.start_time >= 0){
    runtime =  getTimeLineLabel((d.exit_time/1000000) - (d.start_time / 1000000));
    }
    else runtime = 'Runtime data is not available.';


        // Fill in the processDetails section with informationm
    // from the node. Because we want to transition
    // this to match the transitions on the graph,
    // we first set it's opacity to 0.
    processDetails.style({'opacity': 0});


    // Now add the processDetails content.
    let fileNames = d.reads.sort().concat(d.writes.sort());
    let uniqFileNames = [...new Set(fileNames)];


    //  let readFromDivHeader = processDetails.append('div').attr("id", "readFromDivHeader").attr("class", "panel-heading");
    processDetails.append('h3').text("Process:").attr("href", "#ProcessName").style({'padding-left': 0, 'text-decoration': 'none' ,'color':'white' ,  'font-size': '20px' });
    processDetails.append('h5').text(d.name).attr("id", "ProcessName" ).attr("class", "panel-collapse ").style({'padding-left': 0, 'text-decoration': 'none', 'font-size': '15px' });

    processDetails.append('h3').attr("class", "collapsible").append('a').text("Runtime:").attr("href", "#Runtime").attr("data-toggle", "collapse").style({'padding-left': 0, 'text-decoration': 'none' ,'color':'white' ,  'font-size': '20px' });
    processDetails.append('h5').text(runtime).attr("id", "Runtime" ).attr("class", "panel-collapse ").style({'padding-left': 0, 'text-decoration': 'none', 'font-size': '15px' });

    processDetails.append('h3').attr("class", "collapsible").append('a').text("Commands:").attr("href", "#Commands").attr("data-toggle", "collapse").style({'padding-left': 0, 'text-decoration': 'none' ,'color':'white' ,  'font-size': '20px' });
    processDetails.append('h5').text(commands).attr("id", "Commands" ).attr("class", "panel-collapse ").style({'padding-left': 0, 'text-decoration': 'none', 'font-size': '15px' });

    processDetails.append('h3').text("Associated Files:").style({'padding-left': 0, 'text-decoration': 'none' ,'color':'white' ,  'font-size': '20px' });
    processDetails.append('h6').text(uniqFileNames.length + " files").style({'padding-left': 0, 'text-decoration': 'none', 'font-size': '15px' });
    processDetails.append('input').attr("type", "search").attr("class", "fileSearch_input").attr("placeholder", "Search for listing files")
        .style("margin-left", "10px;");

    searchFilesInfoDiv = processDetails.append('div').attr("class", "searchFilesInfoDiv");

    searchFilesList = processDetails.append('div').attr("class", "searchFilesList");


    let filesList = [];

    let fileNamesList = d.reads.sort().concat(d.writes.sort());

    fileNamesList.forEach(function(file){


        let keyName = "\"" + file + "\"";

        if(keyName in fileDict){


            let thisFile = fileDict[keyName];

            filesList.push(thisFile);

        }


    });



    let filelistUL = searchFilesList.append('ul');
    let fileCount = 1;

    filesList.forEach(function(file){

        let id = "faq-" + fileCount;
        let href = "#" + id;

        let fileLi =   filelistUL.append('li').attr("id",id ).attr("class", "noBeforeContent");

        let fileH2 =  fileLi.append('h4');//.text(file.name);
        fileH2.append('a').attr("href", href).text(file.name);

        let fileDiv = fileLi.append('div');


        let proccess_Read = "";
        let proccess_Write = "";


        if(file.reads.length != 0){
            file.reads.forEach(function(process){
                proccess_Read += process + "<br/>"

            });
        }
        else {

            proccess_Read = "Not read by any process."
        }

        if(file.writes.length != 0){
            file.writes.forEach(function(process){
                proccess_Write += process + "<br/>"

            });
        }
        else {

            proccess_Write = "Not written by any process."
        }

        fileDiv.html(
            "<br>" +
            "<h5>From Package:  " +  file.package+ " </h5>" +

            "<h5>Read By: </h5>" +
            proccess_Read
            +
            "<br>"
            +
            "<h5>Written By: </h5>" +
            proccess_Write

        )



        fileCount++;

    });


    searchFilesList.append('div').attr("class", "searchFilesList__notfound").html(
        "<p>No matches were found&hellip; Try &ldquo;bash&rdquo;.</p>"

    );


    // associationString: "reads" or  "writes
    createFileTooTip(searchFilesInfoDiv,d,"reads");
    createFileTooTip(searchFilesInfoDiv,d,"writes");



    let packageNames = d.packages.reads.sort().concat(d.packages.writes.sort());
    let uniqPackageNames = [...new Set(packageNames)];



    searchFilesInfoDiv.append('h3').text("Associated Packages:").style({'padding-left': 0, 'text-decoration': 'none' ,'color':'white' ,  'font-size': '20px' });
    searchFilesInfoDiv.append('h6').text(uniqPackageNames.length + " packages").style({'padding-left': 0, 'text-decoration': 'none', 'font-size': '15px' });

    createPackageTooTip(searchFilesInfoDiv,d);



    // With the content in place, transition
    // the opacity to make it visible.

    processDetails.transition().style({'opacity': 1});


    // 'use strict';


    // search & highlight
    ;( function( $, window, document, undefined )
    {
        let $container = $( '.fileSearch' );
        let $searchFilesListContainer = $container.find( '.searchFilesList' );

        if( !$container.length ) return true;


        let $input			= $container.find( '.fileSearch_input' ),
            $notfound		= $searchFilesListContainer.find( '.searchFilesList__notfound' ),
            $items			= $searchFilesListContainer.find( '> ul > li' ),
            $item			= $(),
            itemsIndexed	= [];

        console.log("searchFilesListContainer:", $searchFilesListContainer);


        $items.each( function()
        {
            itemsIndexed.push( $( this ).text().replace( /\s{2,}/g, ' ' ).toLowerCase() );
        });

        $input.on( 'keyup', function( e )
        {
            console.log('keyup : ');

            $(".searchFilesInfoDiv").hide();
            $(".searchFilesList").show();


            if( e.keyCode === 13 ) // enter
            {

                $input.trigger( 'blur' );
                return true;
            }

            $items.each( function()
            {
                $item = $( this );
                $item.html( $item.html().replace( /<span class="highlight">([^<]+)<\/span>/gi, '$1' ) );
            });

            let searchVal = $.trim( $input.val() ).toLowerCase();
            if( searchVal.length )
            {
                for( let i in itemsIndexed )
                {
                    $item = $items.eq( i );
                    if( itemsIndexed[ i ].indexOf( searchVal ) != -1 )
                        $item.removeClass( 'is-hidden' ).html( $item.html().replace( new RegExp( searchVal+'(?!([^<]+)?>)', 'gi' ), '<span class="highlight">$&</span>' ) );
                    else
                        $item.addClass( 'is-hidden' );
                }
            }
            else {
                $items.removeClass('is-hidden');

                $(".searchFilesInfoDiv").show();
                $(".searchFilesList").hide();

            }

            $notfound.toggleClass( 'is-visible', $items.not( '.is-hidden' ).length === 0 );
        });
    })( jQuery, window, document );


    // toggling items on title press

    ;( function( $, window, document, undefined )
    {
        $( document ).on( 'click', '.searchFilesList h4 a', function( e )
        {
            e.preventDefault();
            $( this ).parents( 'li' ).toggleClass( 'is-active' );
        });
    })( jQuery, window, document );


    // auto-show item content when show results reduces to single

    ;( function( $, window, document, undefined )
    {
        let $container = $( '.fileSearch' );
        let $searchFilesListContainer = $container.find( '.searchFilesList' );

        if( !$container.length ) return true;

        let $input			= $container.find( '.fileSearch_input' ),
            $items			= $searchFilesListContainer.find( '> ul > li' ),
            $item			= $();

        $input.on( 'keyup', function()
        {
            $item = $items.not( '.is-hidden' );
            if( $item.length === 1 )
                $item.addClass( 'js--autoshown is-active' );
            else
                $items.filter( '.js--autoshown' ).removeClass( 'js--autoshown is-active' );
        });
    })( jQuery, window, document );

};


function createFileTooTip(notesDiv,source, associationString){


    let readsList;
    let idString;
    let idString_href;
    let text_String ;

    if(associationString === 'reads'){

        idString = "readsToDiv";
        idString_href = "#readsToDiv";
        text_String = "Reads from:";
        readsList = source.reads.sort();
    }
    else if (associationString === 'writes'){

        idString = "writesToDiv";
        idString_href = "#writesToDiv";
        text_String = "Writes to:";
        readsList = source.writes.sort();

    }



    notesDiv.append('h5').attr("class", "panel-title").append('a').attr("data-toggle", "collapse").attr("href", idString_href).text(text_String).style({'padding-left': 0, 'text-decoration': 'none', 'font': '8 px sans-serif' });

    let readsFromDiv = notesDiv.append('div').attr("id", idString ).attr("class", "panel-collapse ");

    // let readsList = source.writes.sort();
    let packagePath = '';
    let newDetails ;
    let currentUL ;


    if(readsList.length !=0){

        for (let i = 0; i < readsList.length; i++ ){

            packagePath = setPackagePath(readsList, i , i + 1).replace('/','');
            newDetails = readsFromDiv.append('details');

            newDetails.append('summary').text(packagePath);

            currentUL = newDetails.append('ul');

            while(readsList[i].includes(packagePath) ){


                let thisReadArray = ["\"" + readsList[i] + "\""];

                let fileName = readsList[i].replace(packagePath,"");

                currentUL.append('li')
                    .data(thisReadArray)
                    .attr("class", 'noBeforeContent')
                    .on("mouseover", function(d) {


                        let thisFile =  fileDict[d];

                        let proccess_Read = "";
                        let proccess_Write = "";


                        if(thisFile.reads.length != 0){
                            thisFile.reads.forEach(function(process){
                                proccess_Read += process + "<br/>"

                            });
                        }
                        else {

                            proccess_Read = "Not read by any process."
                        }

                        if(thisFile.writes.length != 0){
                            thisFile.writes.forEach(function(process){
                                proccess_Write += process + "<br/>"

                            });
                        }
                        else {

                            proccess_Write = "Not written by any process."
                        }

                        tooltip.transition()
                            .duration(200)
                            .style("opacity", .8);
                        tooltip.html(
                            "<h5 style='font-size: 12px'>" + thisFile.name + " </h5>" +
                            "<h5 style='font-size: 12px'>From Package:  " +  thisFile.package+ " </h5>" +

                            "<h5 style='font-size: 12px'>Read By: </h5>" +
                            proccess_Read
                            +
                            "<br>"
                            +
                            "<h5 style='font-size: 12px'>Written By: </h5>" +
                            proccess_Write

                        )
                            .style("left", (d3.event.pageX) + "px")
                            .style("top", (d3.event.pageY - 28) + "px");

                    })
                    .on("mouseout", function(d) {
                        tooltip.transition()
                            .duration(500)
                            .style("opacity", 0);
                    })
                    .text(fileName.replace('//',''));

                if(readsList[i+1] == null){

                    break;
                }

                if(readsList[i+1].includes(packagePath) == false ){


                    break;


                }
                i++;

            }


        }

    }
    else {
        readsFromDiv.append('details').append('summary').text("No associated file.");

    }


}




function createPackageTooTip(processDetails_Div,source){


    console.log('createPackageTooTip source', source);

    let idString = "package_Div";

    let packageNames = source.packages.reads.sort().concat(source.packages.writes.sort());
    let packages = {};


    packageNames.forEach(function (thisPackage) {

        packages[thisPackage] = {["version"]:"", ["files"]:[]};

        forceData.packages.forEach(function(forceDataPackage){

            if(forceDataPackage.name === thisPackage && forceDataPackage.name != "other_files" ){

                packages[thisPackage].version = "Version: " + forceDataPackage.version;
            }
        })


    });



    let fileList = source.reads.sort().concat(source.writes.sort());

    fileList.forEach(function(file){


        let keyName = "\"" + file + "\"";

        if(keyName in fileDict){


            let thisFile = fileDict[keyName];

            packages[thisFile.package].files.push(thisFile);


        }


    });



    let readsFromDiv = processDetails_Div.append('div').attr("id", idString ).attr("class", "panel-collapse ");


    let newDetails ;
    let newSummary;
    let currentUL ;
    let container;


    if(Object.keys(packages).length !=0){


        Object.keys(packages).forEach(function(key) {


            let summaryText = "";
            if(packages[key].files.length > 1){

                summaryText = key + "    (" +  packages[key].files.length + " files)";
            }
            else {

                summaryText = key + "    (" +  packages[key].files.length + " file)";
            }


            container = readsFromDiv.append('div');

            //
            //                let checkBox =  container.append("foreignObject")
            //                    .attr("width", 100)
            //                    .attr("height", 100)
            //                    .style("float", 'left')
            //                    .style("margin-left", 30)
            //                    .append("xhtml:body")
            //                    .html("<form><input type=checkbox id=check /></form>")
            //                    .on("click", function(d, i){
            //
            //                        console.log(" theck box d:", d);
            //                        console.log(" the source:", source);
            //                       // console.log(svg.select("#check").node().checked);
            //
            //
            //                    });


            newDetails = container.append('details');
            newSummary = newDetails.append('summary').text(summaryText);

            newSummary.on("mouseover", function(d) {


                tooltip.transition()
                    .duration(200)
                    .style("opacity", .8);
                tooltip.html(
                    "<h5 style='font-size: 12px'>" +  packages[key].version + " </h5>"

                ).style("left", (d3.event.pageX) + "px")
                    .style("top", (d3.event.pageY - 28) + "px");



            }).on("mouseout", function(d) {
                tooltip.transition()
                    .duration(500)
                    .style("opacity", 0);
            });


            currentUL = newDetails.append('ul');

            packages[key].files.forEach(function (file) {

                currentUL.append('li')
                    .attr("class", 'noBeforeContent')
                    .text(file.name);

            })

        });


    }
    else {
        readsFromDiv.append('details').append('summary').text("No associated package.");

    }


};

function createAllPackageList(packages){

    //  let packages = {};


    let allPackageListDiv = d3.selectAll(".All_Packages");
    let mainContainer;


    allPackageListDiv.append('h3').text("All Packages:").attr("id", "AllPackagesDiv" ).attr("href", "#AllPackages").attr("data-toggle", "collapse").style({'padding-left': 0, 'text-decoration': 'none' ,'color':'white' ,  'font-size': '20px' });
    // let readsFromDiv = processDetails.append('div').attr("id", idString ).attr("class", "panel-collapse ");
    mainContainer = allPackageListDiv.append('div').attr("id", "AllPackages" ).attr("class", "panel-collapse ");

    mainContainer.append('h6').text(packages.length + " packages").style({'padding-left': 0, 'text-decoration': 'none' ,'color':'#778899' ,  'font-size': '15px' });

    let newDetails ;
    let newSummary;
    let currentUL ;
    let subContainer;



    packages.forEach(function(thisPackage){

        //    packages[thisPackage.name] = {["version"]: thisPackage.version, ["files"]:thisPackage.files};

        let summaryText = "";

        if(thisPackage.files.length > 1){

            summaryText = thisPackage.name + "    (" +  thisPackage.files.length + " files)";
        }
        else {

            summaryText = thisPackage.name + "    (" +  thisPackage.files.length + " file)";
        }

        subContainer = mainContainer.append('div');

        subContainer.append("input")
            .attr("type", "checkbox")
            .attr("width", 100)
            .attr("height", 100)
            .attr("checked", true)
            .style("float", 'left')
            .style("padding-left", 50)
            .style("margin", '1px 10px 1px 1px')
            .on("click", function(d, i){


                let selectedPackage = d3.select(".package_" + thisPackage.name.replace(/[.,\/#!$%\^&\*;:+{}=\-_`~()]/g,""));
                let thisEdge = d3.select("#edge_" +thisPackage.name.replace(/[.,\/#!$%\^&\*;:+{}=\-_`~()]/g,""));
                let thisPackageLabel = d3.select("#packageLabel_" +thisPackage.name.replace(/[.,\/#!$%\^&\*;:+{}=\-_`~()]/g,""));



                if(!d3.select(this).node().checked){


                    selectedPackage.style({
                        "opacity": 0

                    });

                    thisPackageLabel.style({
                        "opacity": 0

                    });

                    thisEdge.style({
                        "opacity": 0

                    });



                }
                else{

                    selectedPackage.style({
                        "opacity": 1

                    });

                    thisPackageLabel.style({
                        "opacity": 1

                    });

                    thisEdge.style({
                        "opacity": 1

                    });


                }



            });


        newDetails = subContainer.append('details');
        newSummary = newDetails.append('summary').text(summaryText);

        newSummary.on("mouseover", function(d) {

            tooltip.transition()
                .duration(200)
                .style("opacity", .8);
            tooltip.html(
                "<h5 style='font-size: 12px'>" + "Version: " + thisPackage.version + " </h5>"

            ).style("left", (d3.event.pageX) + "px")
                .style("top", (d3.event.pageY - 28) + "px");


        }).on("mouseout", function(d) {
            tooltip.transition()
                .duration(500)
                .style("opacity", 0);
        });


        currentUL = newDetails.append('ul');

        thisPackage.files.forEach(function (file) {

            currentUL.append('li')
                .attr("class", 'noBeforeContent')
                .text(file.name);

        })


    })




};


function treeDraw(currentJson){




    // d3.json block
    d3.json(currentJson, function(error, data){


        if (error) throw error;

        let tempMaxRunTime = 0;



        data.packages.forEach(function (thisPackage) {

            thisPackage.files.forEach(function (file) {

                let keyName = "\"" + file + "\"";

                let fileInfo = [];
                fileInfo["reads"] =[];
                fileInfo["writes"] =[];
                fileInfo["package"] = thisPackage.name;
                fileInfo["name"] = file;

                fileDict[keyName] = fileInfo;



            })
        });


        data.other_files.forEach(function (file) {


            let keyName = "\"" + file + "\"";

            let fileInfo = [];
            fileInfo["reads"] =[];
            fileInfo["writes"] =[];
            fileInfo["package"] ='other_files';
            fileInfo["name"] = file;

            fileDict[keyName] = fileInfo;


        });



        data.runs.forEach(function (run) {

            run.processes.forEach(function(_process) {

                //preparing data for timeline
                taskNames.push(_process.long_name);

                generateProcessesForTimeLine(_process);




                if(_process.reads != null){

                    _process.reads.forEach(function(file){

                        let keyName = "\"" + file + "\"";



                        if( keyName in fileDict){

                            //console.log('filesDict[file]:', filesDict[keyName]);

                            fileDict[keyName].reads.push(_process.long_name);

                        }

                    });

                };


                if (_process.writes != null){
                    _process.writes.forEach(function(file){



                        let keyName = "\"" + file + "\"";

                        if(keyName in fileDict){


                            fileDict[keyName].writes.push(_process.long_name);

                        }


                    });
                }


            })


        });

        console.log('processes: ', processes);


        let tempPackageX = 0;
        let tempPackageY = -100;
        let isAlternativeOn = 0;
        let sections = [];

        //Handle Packages to create force data
        data.packages.forEach(function (thisPackage) {


            let newPackage = {["name"]: thisPackage.name, ["version"]: thisPackage.version, ["section"] : thisPackage.section, ["files"] : [] , ["cx"]: 0, ["cy"]: tempPackageY , ["OGy"]: tempPackageY, ["color"]: "" , ["radius"] : maxRadius};

            thisPackage.files.forEach(function (file) {


                let keyName = "\"" + file + "\"";

                let thisFile =  fileDict[keyName];
                newPackage.files.push(thisFile);

                // forceNodes.nodes.push(thisFile);

            });


            newPackage.cx = tempPackageX;
            newPackage.OGX = tempPackageX;

            //Dynamically set the distances between nodes by number of packages
            if(data.packages.length > 15 && data.packages.length < 30 ){

                tempPackageX = tempPackageX + ((width /3) / data.packages.length); // 200;
            }
            else if(data.packages.length > 30){

                tempPackageX = tempPackageX + ((width /1.8) / data.packages.length); // 200;
            }
            else {

                tempPackageX = tempPackageX + (width / 4 / data.packages.length); // 200;
            }


            //push this package's section to local sections
            sections.push(newPackage.section);

            //push this package to the forceData
            forceData.packages.push(newPackage);

            //increase packagesNumber to keep the over package number in record
            packagesNumber++;

            // set alternative Y position for force nodes
            if(isAlternativeOn === 0 && data.packages.length > 15){

                tempPackageY = -60;

                isAlternativeOn = 1;
            }
            else if (isAlternativeOn === 1){

                tempPackageY = -100;
                isAlternativeOn = 0;

            }




        });

        console.log('forceData:' , forceData);


        //Set sections colors for packages from local sections
        setSectionsColors(sections);




        //Create the all package list on the overview section on sidebar
        createAllPackageList(forceData.packages);



        //Handle runs
        data.runs.forEach(function(run){

            console.log('run.name: ', run.name);

            runNames.push(run.name);

            rawData[run.name] = [];
            treeData[run.name] = [];

            run.processes.forEach(function(_process){

                let packages = {["reads"]:[], ["writes"]: []};
                let packagesName = [];

                if(_process.parent == null){

                    let node = {["name"]: _process.long_name, ["parent"]: "null", ["rule"] : "null", ["description"]: _process.description, ["reads"]: _process.reads ,  ["writes"]: _process.writes  ,["argv"]: _process.argv  , ["start_time"] : _process.start_time , ["exit_time"] : _process.exit_time};


                    if(_process.reads != null){

                        _process.reads.forEach(function(file){

                            let keyName = "\"" + file + "\"";

                            if( keyName in fileDict){

                                packages.reads.push(fileDict[keyName].package);
                                packagesName.push(fileDict[keyName].package);

                            }

                        });

                        let uniq = [...new Set(packages.reads)];
                        packages.reads = uniq;
                    };



                    if (_process.writes != null){
                        _process.writes.forEach(function(file){



                            let keyName = "\"" + file + "\"";

                            if(keyName in fileDict){

                                packages.writes.push(fileDict[keyName].package);
                                packagesName.push(fileDict[keyName].package);

                            }


                        });

                        let uniq = [...new Set(packages.writes)];
                        packages.writes = uniq;
                    }

                    node.packages = packages;

                    let uniq = [...new Set(packagesName)];
                    node.packageNames = uniq;


                    if(_process.exit_time > tempMaxRunTime ){

                        tempMaxRunTime = _process.exit_time;
                    }

                    rawData[run.name].push(node);

                }
                else {

                    let parentProcess = run.processes[ ( _process.parent[0] ) ];

                    let node = {["name"]: _process.long_name, ["parent"]: parentProcess.long_name, ["rule"] : _process.parent[1], ["description"]: _process.description ,  ["reads"]: _process.reads ,  ["writes"]: _process.writes ,["argv"]: _process.argv , ["start_time"] : _process.start_time , ["exit_time"] : _process.exit_time};


                    // let filesDict = {} ;

                    if(_process.reads != null){

                        _process.reads.forEach(function(file){

                            let keyName = "\"" + file + "\"";

                            //console.log('Inner keyName:', fileDict[keyName]);
                            //console.log('keyName:', keyName);

                            if( keyName in fileDict){

                                // console.log('filesDict[file] package Name:', fileDict[keyName].package);

                                packages.reads.push(fileDict[keyName].package);
                                packagesName.push(fileDict[keyName].package);
                                //filesDict[keyName].reads.push(_process.long_name);

                            }

                        });

                        let uniq = [...new Set(packages.reads)];
                        packages.reads = uniq;
                    };



                    if (_process.writes != null){
                        _process.writes.forEach(function(file){



                            let keyName = "\"" + file + "\"";

                            if(keyName in fileDict){

                                packages.writes.push(fileDict[keyName].package);
                                packagesName.push(fileDict[keyName].package);

                            }

                        });

                        let uniq = [...new Set(packages.writes)];
                        packages.writes = uniq;
                    }

                    node.packages = packages;

                    let uniq = [...new Set(packagesName)];
                    node.packageNames = uniq;


                    if(_process.exit_time > tempMaxRunTime ){

                        tempMaxRunTime = _process.exit_time;
                    }

                    rawData[run.name].push(node);


                }


            });

            console.log('rawData:', rawData[run.name]);

            /*-- create treeData --*/
            let dataMap = rawData[run.name].reduce(function(map, node) {
                map[node.name] = node;
                return map;
            }, {});


            rawData[run.name].forEach(function(node) {
                // add to parent
                let parent = dataMap[node.parent];
                if (parent) {
                    // create child array if it doesn't exist
                    (parent.children || (parent.children = []))
                    // add node to child array
                        .push(node);
                } else {
                    // parent is null or missing
                    treeData[run.name].push(node);
                }
            });


            console.log('treeData:', treeData[run.name]);


        });



        // function collapse(d) {
        //
        //     if (d.children) {
        //
        //         // Set default timeline length for root Check for the tree node size instead of double counting length
        //         if(!isTreeRedrawn){
        //             timeLineLen_Total =  timeLineLen_Total + 400;// (root.x0  / 2);
        //
        //         }
        //
        //
        //         d._children = d.children;
        //         d._children.forEach(collapse);
        //         d.children = null;
        //     }
        //
        //
        // }


       // timeLineLen_Total = tree.size()[1];




        let runNametDiv = d3.select("#thisRunName");

        runNametDiv.append('h3').text("Run Name:").attr("href", "#thisRunName").attr("data-toggle", "collapse").style({'padding-left': 0, 'text-decoration': 'none' ,'color':'white' ,  'font-size': '20px' });

        runNametDiv.append('h5').text(runNames[0]).attr("id", "thisRunName" ).attr("class", "panel-collapse ").style({'padding-left': 0, 'text-decoration': 'none', 'font-size': '15px' });



        root = treeData[runNames[0]][0];
        root.x0 = height; // / 2;
        root.y0 = 1000;
        root.y = 1000;


        console.log('height: ', height);
        console.log('root.y0: ', root.y0);

        console.log('root: ', root);




        //Time line code block

        // rootStartTime = root.start_time;
        rootStartTime = treeData[runNames[0]][0].start_time;

        console.log('rootStartTime:', rootStartTime);

        let duration_ms = 0;

        let duration;

        let durationLabel  = '';

        duration_total_ms =  0 ;

        let durationLabel_total  = 'No timeline data available for this experiment';

        timeLineLen_Total = 0;


        // timeLineLen = root.x0 / 2;


        if(root.children!=null){

            root.children.forEach(collapse);
        }

        console.log('maxcCountCollapse: ', maxcCountCollapse);



        if (rootStartTime >= 0 && root.children!=null){


            duration_ms = (root.children[0].start_time - rootStartTime) / 1000000;

            duration = new moment.duration(duration_ms);

            durationLabel  = "Cumulatively took " + duration.asMilliseconds().toFixed(2) + " milliseconds" +  " when " + root.children[0].name + " is started.";

            duration_total_ms =  (tempMaxRunTime - rootStartTime) / 1000000 ;

            durationLabel_total  = getTimeLineLabel(duration_total_ms,"total");

            timeLineLen_Total =  (maxcCountCollapse + 1) * 400;



        }





        console.log('countCollapse: ', countCollapse);
        console.log('maxcCountCollapse: ', maxcCountCollapse);


        console.log('timeLineLen_Total: ', timeLineLen_Total);

        timeLineLen =  timeLineLen_Total * (duration_ms / duration_total_ms);

          console.log('timeLineLen: ', timeLineLen);

        if(!isTreeRedrawn){


            totalTimeLineDraw(timeLineLen_Total , durationLabel_total);
            timeLineDraw(timeLineLen  , durationLabel);


        }
        else{

            updateTimeLine(timeLineLen,durationLabel);

        }


        update(root);

        //Call Force Draw function
        forceDraw(forceData);

        // createPackageTooTip(searchFilesInfoDiv,d);

       console.log('tree.size(): ',tree.size());

       //[1103, 6336]


    })

};



//Need to fix the diplay of time

function getTimeLineLabel(duration_ms, isTotalString){

    let duration_total = new moment.duration(duration_ms);

    let durationLabel_total  = '';



    if(duration_total.asMilliseconds() < 1000){

        durationLabel_total =  duration_total.asMilliseconds().toFixed(2) + " milliseconds";

    }
   if (duration_total._data.seconds > 0){

        durationLabel_total =  duration_total._data.seconds + " seconds and " + duration_total._data.milliseconds.toFixed(2) + " milliseconds";

    }

   if (duration_total._data.minutes > 0 ){

        durationLabel_total =   duration_total._data.minutes + " minutes and " + duration_total._data.seconds + "." + duration_total._data.milliseconds.toFixed(0) + " seconds";

    }
    if ( duration_total._data.hours > 0){

        durationLabel_total =   duration_total._data.hours + " hours and " + duration_total._data.minutes + " minutes" ;


    }
    if (duration_total._data.days > 0){

        durationLabel_total =   duration_total._data.days + " days and " + duration_total._data.hours + " hours" ;

    }

    if (isTotalString === "total"){

        durationLabel_total = "Total " + durationLabel_total;
    }else if (isTotalString === "took"){

        durationLabel_total = "Cumulatively took "  + durationLabel_total +  " when " ;
    }
    else{


    }

    return durationLabel_total;


};

function timeLineDraw(length, durationLabel){

    //  Draw the timeline for currentduration
    svg.append("g")
        .attr("class", "timeLineGroup")
        .append("line")
        .attr("class", "timeLine")
        .attr("x1", 0)
        .attr("y1", height  )
        .attr("x2", length)
        .attr("y2", height )
        .attr("stroke-width", 5)
        .attr("stroke", "#dbbd5a");



    // Update the link text
    svg.selectAll(".timeLineGroup").append("text")
        .attr("y", height + 20)//magic number here
        .attr("x", (length / 2) +  margin.left)
        .attr('text-anchor', 'middle')
        .attr("class", "timeLineText")//easy to style with CSS
        .text(durationLabel);



};

function totalTimeLineDraw(length, durationLabel){

    // Draw the timeline for total duration.
    svg.append("g")
        .attr("class", "TotalTimeLineGroup")
        .append("line")
        .attr("class", "timeLine_Total")
        .attr("x1", 0)
        .attr("y1", height )
        .attr("x2", length)
        .attr("y2", height )
        .attr("stroke-width", 5)
        .attr("stroke", "#5adbbd");



    // Update the link text
    svg.selectAll(".TotalTimeLineGroup").append("text")
        .attr("y", height + 20)//magic number here
        .attr("x", length  )
        .attr('text-anchor', 'middle')
        .attr("class", "totalTimeLineText")//easy to style with CSS
        .text(durationLabel);



};

function removeSvg(){

    console.log('svg: ',     svg);

    svg.remove();
};



function renderGanttChart(){

    svg.remove();

    // let viz = svg.selectAll(".package");
    //
    // let forcePackages = svg.selectAll(".package");
    // let label = svg.selectAll(".forceLabel");
    // let edge = svg.selectAll(".edge");
    //
    //
    //
    // let node = svg.selectAll("g.node");
    // let link = svg.selectAll("path.link");
    // let linktext = svg.selectAll("g.link");
    // let timeLineText = d3.selectAll(".timeLineText");
    //
    // let timeline =  svg.selectAll(".timeLine");
    //
    //
    // let timeLine_Total = d3.selectAll(".timeLine_Total");
    // let totalTimeLineText = d3.selectAll(".totalTimeLineText");
    //
    //
    // forcePackages.remove();
    // label.remove();
    // edge.remove();
    //
    // node.remove();
    // link.remove();
    // linktext.remove();
    // timeLineText.remove();
    // timeline.remove();
    // timeLine_Total.remove();
    // totalTimeLineText.remove();
    //
    //
    //
    // forceData = {"packages": []};
    // packagesNumber = 0;
    // sectionsInPackages = {};
    //
    //
    // force.nodes = null;
    // force.links = null;

    // forceNodes = force.nodes;
    // forceLinks = force.links();

   // treeDraw(currentJsonFile);


    processes.sort(function(a, b) {
        return a.endDate - b.endDate;
    });


    var maxDate = processes[processes.length - 1].endDate;



    processes.sort(function(a, b) {
        return a.startDate - b.startDate;
    });

    var minDate = processes[0].startDate;

    console.log( 'maxDate - minDate: ', maxDate - minDate);


    let format = ".%Lms";

    if(( maxDate - minDate) > 1000){

        format = ":%Ss";
    };


    var gantt = d3.gantt().taskTypes(taskNames).taskStatus(taskStatus).tickFormat(format);
    gantt(processes);


}



function generateProcessesForTimeLine(_process){




    var startDate = _process.start_time/1000000;

    // console.log( '_process.start_time: ', _process.start_time / 1000000);
    //
    // console.log( 'startDate: ', startDate.toString("MMM dd"));


    var endDate = _process.exit_time/1000000;

    // console.log( '_process.exit_time: ', _process.exit_time / 1000000);
    // console.log( 'endDate: ', endDate);

    let timeLineProcess = {['startDate']: new Date(startDate),['endDate']: new Date(endDate), ['taskName']: _process.long_name , "status":"RUNNING" };

    //
    // //let timeLineProcess = {['startDate']: new Date(_process.start_time/1000000),['endDate']: new Date(_process.exit_time/1000000), ['taskName']: _process.long_name , "status":"RUNNING" };
    //
    // console.log('timeLineProcess.endDate - timeLineProcess.endDate.startDate: ', timeLineProcess.endDate );

    processes.push(timeLineProcess);


    // console.log( '_process.start_time: ', _process.start_time / 1000000);

};


function restart() {


    edge = edge.data(forceLinks);

    edge.enter().insert("line", ".package")
        .attr("class", "edge")
        .attr("id",  function(d){
            return  "edge_" + d.target.name})
        .attr("x1", function(d){ return d.source.x;
        })
        .attr("y1", function(d){ return d.source.y; })
        .attr("x2", function(d){ return d.target.x; })
        .attr("y2", function(d){ return d.target.y; });

    //
    //        forcePackages = forcePackages.data(forceNodes);
    //        forcePackages
    //            .attr("cx", function (d) {
    //
    //                  console.log(("d.x: " , d.x));
    //                return d.x;
    //            })
    //            .attr("cy", function (d) {
    //                return d.y;
    //            });



    //        label = label.data(forceNodes);
    //        label.attr("x", function(d){ return d.x; })
    //            .attr("y", function (d) {return d.y - 30; });

    force.start();
};


function restart2() {


    edge = edge.data(forceLinks);

    edge.enter().insert("line", ".package")
        .attr("class", "edge")
        .attr("id",  function(d){
            return  "edge_" + d.target.name})
        .attr("x1", function(d){ return d.source.y;
        })
        .attr("y1", function(d){ return d.source.x; })
        .attr("x2", function(d){ return d.target.y; })
        .attr("y2", function(d){ return d.target.x; });

    //
    //        forcePackages = forcePackages.data(forceNodes);
    //        forcePackages
    //            .attr("cx", function (d) {
    //
    //                  console.log(("d.x: " , d.x));
    //                return d.x;
    //            })
    //            .attr("cy", function (d) {
    //                return d.y;
    //            });



    //        label = label.data(forceNodes);
    //        label.attr("x", function(d){ return d.x; })
    //            .attr("y", function (d) {return d.y - 30; });

    force.start();
};


// Move nodes toward cluster focus.
function gravity(alpha) {
    return function (d) {
        d.y += (d.cy - d.y) * alpha;
        d.x += (d.cx - d.x) * alpha;
    };
};


// Resolve collisions between nodes.
function collide(alpha) {
    let quadtree = d3.geom.quadtree(forceNodes);
    return function (d) {
        let r = d.radius + maxRadius + padding,
            nx1 = d.x - r,
            nx2 = d.x + r,
            ny1 = d.y - r,
            ny2 = d.y + r;
        quadtree.visit(function (quad, x1, y1, x2, y2) {
            if (quad.point && (quad.point !== d)) {
                let x = d.x - quad.point.x,
                    y = d.y - quad.point.y,
                    l = Math.sqrt(x * x + y * y),
                    r = d.radius + quad.point.radius + (d.color !== quad.point.color) * padding;
                if (l < r) {
                    l = (l - r) / l * alpha;
                    d.x -= x *= l;
                    d.y -= y *= l;
                    quad.point.x += x;
                    quad.point.y += y;
                }
            }
            return x1 > nx2 || x2 < nx1 || y1 > ny2 || y2 < ny1;
        });
    };

};


function tick(e) {

    edge.attr("x1", function(d){

        //console.log("mapping link");
        return d.source.x;
    })
        .attr("y1", function(d){ return d.source.y; })
        .attr("x2", function(d){ return d.target.x; })
        .attr("y2", function(d){ return d.target.y; });


    forcePackages
        .each(gravity(0.15 * e.alpha))
        .each(collide(0.2))
        .attr("cx", function (d) {

            //  console.log(("d.x: " , d.x));
            return d.x;
        })
        .attr("cy", function (d) {
            return d.y;
        });


    label.attr("x", function(d){ return d.x; })
        .attr("y", function (d) {return d.y - 30; });
};

function forceDraw(data) {


    let nodes = data.packages;


    force = d3.layout.force()
        .nodes(nodes)
        .size([ width, height])
        .linkDistance(300)
        .linkStrength(0.5)
        .gravity(0)
        .charge(-100)
        .on("tick", tick);


    forceNodes = force.nodes();
    forceLinks = force.links();

    console.log("forceNodes: ", forceNodes );

   // let forceGroup = svg.append("g").attr("id", "forceGroup").attr("transform", "translate(" + width / 2 + "," + height / 2 + ")");


    // forcePackages
    forcePackages = forcePackages
        .data(forceNodes)
        .enter().append("circle")
        .attr("class", 'package')
        .attr("class", function(d){
            return "package    package_"+ d.name.replace(/[.,\/#!$%\^&\*;:+{}=\-_`~()]/g,"");

        })
        .attr("id", function(d){
            return "package"            //  return "package_"+ d.name.replace(/[.,\/#!$%\^&\*;:+{}=\-_`~()]/g,"");

        })
        .attr("r", function (d) {
            return d.radius;
        })
        .style("fill",function(d) {


            if(d.section === sectionsInPackages[d.section].name){

                return sectionsInPackages[d.section].color;
            }

            return   "#4c366d" ; // reutn default ReproZip Color
        })
        .on("click", function(d) {




            let links = force.links();

            links = [];


            edge = svg.selectAll(".edge").data(links);


            let edgeExit = edge.exit().remove();


            if(forceNodes.length > packagesNumber){

                forceNodes.pop();


            }


            let associatedProcesses = [];
            //
            //                if (d.name != "other_files"){
            //
            //
            //
            //
            //                }

            //
            d.files.forEach(function(file){


                file.reads.forEach(function(process){

                    associatedProcesses.push(process);

                })

            });


            console.log( "Before " +  d.name + " associatedProcesses", associatedProcesses);



            let uniq = [...new Set(associatedProcesses)];
            associatedProcesses = uniq;


            console.log( d.name + " associatedProcesses", associatedProcesses);


            // let currentDisplayingNodes = tree.nodes(root).reverse();


            console.log("currentDisplayingNodes", currentDisplayingNodes);

            currentDisplayingNodes.forEach(function(process){

                associatedProcesses.forEach(function(processName){

                    if(process.name === processName){

                        console.log("Same process: ", processName);

                        console.log("The process: ", process);

                        console.log("The d: ", d);

                        process.fixed = true;


                        let node = {};
                        node.x = process.y;
                        node.y = process.x;
                        node.px = process.y;
                        node.py = process.x;
                        node.weight = 10;
                        node.fixed = true;

                        let thisNode  = forceNodes.push(node);


                        links.push({source: d , target: node});

                    }

                })

            });


            forceLinks = links;

            let label = svg.selectAll(".forceLabel")
                .data(force.nodes());

            label.attr("x", function(d){ return d.x; })
                .attr("y", function (d) {return d.y - 30; });

            force.links(links);


            restart2();

        })
        .on("mouseover", function(d) {

            tooltip.transition()
                .duration(200)
                .style("opacity", .8);
            tooltip .html(
                d.name + "<br>" + "section: "+ d.section + "<br>" + "version: " + d.version
            )
                .style("left", (d3.event.pageX) + "px")
                .style("top", (d3.event.pageY - 38) + "px");
        })
        .on("mouseout", function(d) {
            tooltip.transition()
                .duration(500)
                .style("opacity", 0);
        })
        .call(force.drag);


    //forceGroup.append(forcePackages);



    label = label
        .data(forceNodes)
        .enter()
        .append("text")
        .text(function (d) { return d.name; })
        .attr("class", "packageLabel")
        .attr("id", function (d) { return  "packageLabel_" + d.name.replace(/[.,\/#!$%\^&\*;:+{}=\-_`~()]/g,""); })
        .style("text-anchor", "middle")
        .style("fill", "#555")
        .style("font-family", "Arial")
        .style("font-size", 15);


    restart();

};




function updateTimeLine(length, durationLabel){

    let timeline =  svg.selectAll(".timeLine");

    timeline.transition()
        .attr("x2", length);


    let timeLineText = d3.selectAll(".timeLineText")
        .transition()
        .attr("x", (timeLineLen / 2) + 50)
        .attr('text-anchor', 'middle')
        .attr("class", "timeLineText")//easy to style with CSS

        .text(durationLabel);

};


function decreaseTimeLineLen(length){

    if((timeLineLen - ( length) >= 0)) {

        timeLineLen =  length //timeLineLen - ( length);
    }

};

function setPackagePath (fileList, index, nextIndex){

    // console.log('nextIndex: ', nextIndex);

    let TestingPackagePath = '';

    if(fileList[nextIndex] != null){


        a1_Len =  fileList[index].length;
        let i = 0;

        while(i < a1_Len && fileList[index].charAt(i)===fileList[nextIndex].charAt(i)){

            i++
        }

        if (fileList[index].substring(0,i) === '/'){


            // console.log('different character: ',fileList[index].substring(0,i));

            TestingPackagePath = fileList[index].substring(0, fileList[index].lastIndexOf('/'));
            //  console.log('TestingPackagePath: ',TestingPackagePath);

        }
        else {


            TestingPackagePath = fileList[index].substring(0,i);
            TestingPackagePath = TestingPackagePath.substring(0, TestingPackagePath.lastIndexOf('/'));
            // console.log('TestingPackagePath: ',TestingPackagePath);

        }


    }
    else {

        TestingPackagePath = fileList[index].substring(0, fileList[index].lastIndexOf('/'));

    }

    return TestingPackagePath;

};


function resetPackagesPosition(){


    if (thisNodeCircle != null && thisNodeCircleLabel != null){


        thisNodeCircle.transition().attr("r", 8);
        thisNodeCircleLabel.transition().style("font", "15px sans-serif").attr("x", function(d) { return d.children || d._children ? -10 : 10; });


    }

    links = [];

    edge = svg.selectAll(".edge").data(links);

    let edgeExit = edge.exit().remove();
    let circles = svg.selectAll("circle");

    forceLinks = links;

    force.links(links);

    restart();
};

function setSectionsColors(sections){

    //make the sections as unique set
    let uniq = [...new Set(sections)];
    sections = uniq;

    let linearScale = d3.scale.linear().domain([0, sections.length]).range([0,400]);

    let i = 0;

    sections.forEach(function(section){


        let thisSection = [];
        thisSection["name"] = section;
        thisSection["color"] = "hsl(" + linearScale(i) + ",60%,80%)";

        sectionsInPackages[section] = thisSection;

        i++;

    });
};



let countCollapse = 0;
let maxcCountCollapse = 0;


function collapse(d) {

    if (d.children) {

        // Set default timeline length for root
        // if(!isTreeRedrawn){
        //     timeLineLen_Total =  timeLineLen_Total + 400;// (root.x0  / 2); //timeLineLen_Total + (root.x0  / 2);
        //
        // }

        countCollapse++;

        d._children = d.children;
        d._children.forEach(collapse);
        d.children = null;
    }


    if (countCollapse > maxcCountCollapse){

        maxcCountCollapse = countCollapse;

        countCollapse = 0;
    }


};


function expand(d){
    let children = (d.children)?d.children:d._children;
    if (d._children) {
        d.children = d._children;
        d._children = null;
    }
    if(children)
        children.forEach(expand);
};

function expandAll(){

    resetPackagesPosition();

    expand(root);
    update(root);
}

function collapseAll(){


    resetPackagesPosition();

    root.children.forEach(collapse);
    collapse(root);
    update(root);
};



