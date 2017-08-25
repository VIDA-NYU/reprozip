
/*-- GLobal sidebar variables  --*/

let searchFilesInfoDiv;
let searchFilesList;

// SideBar Process Details - Select the container for the processDetails and set the dimensions.
const processDetails = d3.select('#processDetails')
    .style({
        'width': 620-width + 'px',
        'height': height + 'px',
        'margin-top' : 0 + 'px'
    });







/*-- Bootstrap buttons events handler in Sidebar "Overview" section --*/

$(function() {

    /*-- Handel toggle button for focusing selected process and associated packages  --*/
    $('#toggle-inFocus').change(function() {

        inFocus = $(this).prop('checked');

        if(!inFocus){
            let otherSVG = d3.selectAll(".process, .processLabel, .package, .edge, .packageLabel, .link");

            otherSVG.transition().style("opacity", 1);

        }
        else{
            let otherSVG = d3.selectAll(".process, .processLabel, .package, .edge, .packageLabel, .link");

            otherSVG.transition().style("opacity", 0.3);

            thisNodeCircle.transition().attr("r", 20).style("opacity", 1);
            thisNodeCircleLabel
                .transition()
                .style("font", "20px sans-serif")
                .style("opacity", 1)
                .attr("x", function(d) { return d.children || d._children ? -30 : 30; });


            forceNodes.forEach(function(target) {

                currentSelectedNode.packages.reads.forEach(function (readFile) {

                    {
                        if(target.name === readFile)
                            console.log("d3.select:",d3.select("#package_" + readFile.replace(/[.,\/#!$%\^&\*;:+{}=\-_`~()]/g,"")).style("opacity", 1));

                        d3.select("#package_" + readFile.replace(/[.,\/#!$%\^&\*;:+{}=\-_`~()]/g,"")).style("opacity", 1);
                        d3.select("#packageLabel_" + readFile.replace(/[.,\/#!$%\^&\*;:+{}=\-_`~()]/g,"")).style("opacity", 1);


                    }
                })
            });

        }
    });


    $('#packages_ConnectAll').on("click", function (e) {


        let links = force.links();

        links = [];


        edge = svg.selectAll(".edge").data(links);


        let edgeExit = edge.exit().remove();


        while(forceNodes.length > packagesNumber){

            forceNodes.pop();


        };

        let associatedProcesses = [];
        //
        //                if (d.name != "other_files"){
        //
        //
        //
        //
        //                }

        //


        forceNodes.forEach(function(thisPackage){

            associatedProcesses = [];

            thisPackage.files.forEach(function(file){


                file.reads.forEach(function(process){

                    associatedProcesses.push(process);

                });


            });



            let uniq = [...new Set(associatedProcesses)];
            associatedProcesses = uniq;



            currentDisplayingNodes.forEach(function(process){

                associatedProcesses.forEach(function(processName){

                    if(process.name === processName){


                        process.fixed = true;


                        let node = {};
                        node.x = process.y;
                        node.y = process.x;
                        node.px = process.y;
                        node.py = process.x;
                        node.weight = 10;
                        node.fixed = true;

                        forceNodes.push(node);


                        links.push({source: thisPackage , target: node});

                    }

                })

            });

        });

//                  console.log("associatedProcesses", associatedProcesses);
//
//                  console.log("currentDisplayingNodes", currentDisplayingNodes);
//


        forceLinks = links;

        let label = svg.selectAll(".forceLabel")
            .data(force.nodes());

        label.attr("x", function(d){ return d.x; })
            .attr("y", function (d) {return d.y - 30; });

        force.links(links);


        restart2();




    });







    /*-- Handel buttons for collapsing or expanding all nodes for the network tree --*/
    $('#tree_CloseAll').on("click", function (e) {

        collapseAll();

    });

    $('#tree_ExpandAll').on("click", function (e) {

        expandAll();

    });


    $('#timeLineShow').on("click", function (e) {

        console.log('graphShow');

        renderGanttChart();

    });


    $('#graphShow').on("click", function (e) {


        //removeSvg();
        location.reload();

        // let timeline = svg.selectAll(".chart");
        // timeline.remove();



        //treeDraw(currentJsonFile);

    });


});
