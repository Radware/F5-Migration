$(document).ready(function(){
    $('#validateNameBtn').click(function (){
        var ProjectName = $('#ProjectName').val();
        var dataString = 'ProjectName='+ ProjectName +'';
        $.ajax({
            method: 'POST',
            url: '/validate_name',
            data: dataString,
            contentType: 'application/x-www-form-urlencoded',
            success: function(data) {
                if (data === 'ok') {
                    alert('File ' + ProjectName + ' does not exist.\nYou can continue to the next step.');
                } else if (data === 'empty') {
                    alert('Error!\nPlease input a file name.');
                } else {
                    alert('Error!\nFile ' + ProjectName + ' already exists.\nPlease choose another file name.');
                }
            },
        });
    });
});
