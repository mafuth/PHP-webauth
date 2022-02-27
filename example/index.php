<title>Biometric lock</title>
<div id="alerts"></div>
<br>
<button id="verify">Verify</button>
<br><br><br>
<button id="register">Regsiter</button>
<script src="/js/webauthnauthenticate.js"></script>
<script src="/js/webauthnregister.js"></script>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
<script>
$('#register').click(function(){
  $.ajax({
      type:'POST',
      url:'register.php',
      data:{
        get:'challenge',
      },
      dataType: 'json',
      beforeSend:function(){
        $('#register').hide(); 
      },
      success:function(data){
        $('#alerts').html(data);
        webauthnRegister(data.challenge, function(success, info){
          if(success){
            $.ajax({
                type:'POST',
                url:'register.php',
                data:{
                  get:'register',
                  register: info,
                },
                dataType: 'json',
                beforeSend:function(){
                  $('#register').hide(); 
                },
                success:function(data){
                  $('#register').show();
                  $('#alerts').html(data); 
                },
                error: function(xhr, status, error){
                  $('#alerts').html("register failed: "+error+": "+xhr.responseText);
                }
            });
          }
        }); 
      },
      error: function(xhr, status, error){
        $('#alerts').html("couldn't initiate register: "+error+": "+xhr.responseText);
      }
  });
});
$('#verify').click(function(){
    $.ajax({
        type:'POST',
        url:'loggin.php',
        data:{
          get:'challenge',
        },
        dataType: 'json',
        beforeSend:function(){
          $('#verify').hide(); 
        },
        success:function(data){
          $('#alerts').html(data);
					webauthnAuthenticate(data.challenge, function(success, info){
            if(success){
              $.ajax({
                  type:'POST',
                  url:'loggin.php',
                  data:{
                    get:'loggin',
                    login: info,
                  },
                  dataType: 'json',
                  beforeSend:function(){
                    $('#verify').hide(); 
                  },
                  success:function(data){
                    $('#verify').show();
                    $('#alerts').html(data); 
                  },
                  error: function(xhr, status, error){
                    $('#alerts').html("auth failed: "+error+": "+xhr.responseText);
                  }
              });
            }else{ 
              $('#alerts').html('auth build failed');
            }
          }); 
        },
        error: function(xhr, status, error){
          $('#alerts').html("couldn't initiate login: "+error+": "+xhr.responseText);
        }
    });
});
</script>