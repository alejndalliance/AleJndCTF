$("#flag-submission").click(function() {
	var flag = $("#flag-input").val();

	var id = $("#task-id").val()

    $.ajax({
        url: "/submit/" + id + "/" + btoa(flag)
    }).done(function(data) {

        console.log(data);

        if (data["success"]) {
            $("#flag-input").val($(".lang").data("success"));
            $("#flag-submission").removeClass("btn-primary");
            $("#flag-submission").addClass("btn-success");
            $("#flag-submission").attr('disabled','disabled');
        } else {
            $("#flag-input").val($(".lang").data("failure"));
        }
    });
});

$("#attack-submission").click(function() {
    var flag = $("#attack-input").val();

    $.ajax({
        url: "/attack/submit/" + btoa(flag)
    }).done(function(data) {

        console.log(data);

        if (data["success"]) {
            $("#attack-input").val($(".lang").data("success"));
        } else {
            $("#attack-input").val($(".lang").data("failure"));
        }
    });
});
