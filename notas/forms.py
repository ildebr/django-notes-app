from django import forms
from .models import Nota
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, UsernameField
from django.contrib.auth.models import User
from django.contrib.auth.forms import (AuthenticationForm, PasswordResetForm,
                                   SetPasswordForm)

class NotaUsuarioForm(forms.ModelForm):
    class Meta:
        model = Nota
        fields = [
            "titulo",
            "texto"
        ]
    def __init__(self, *args, **kwargs):
        super(NotaUsuarioForm, self).__init__(*args, **kwargs)
        self.fields['titulo'].widget.attrs.update({'class': 'input-field note-title', 'placeholder': 'Titulo'})
        self.fields['texto'].widget.attrs.update({'class': 'input-field note-text', 'placeholder': 'Contenido'})





class NewUserForm(UserCreationForm):
    email = forms.EmailField(required=True)

    def __init__(self, *args, **kwargs):
        super(NewUserForm, self).__init__(*args, **kwargs)
        self.fields['email'].widget.attrs.update({'class': 'input_field', 'required': 'required'})
        self.fields['username'].widget.attrs.update({'class': 'input_field', 'required': 'required'})
        self.fields['password1'].widget.attrs.update({'class': 'input_field', 'required': 'required'})
        self.fields['password2'].widget.attrs.update({'class': 'input_field', 'required': 'required'})

    class Meta:
        model = User
        fields = ("username", "email")
    
    def save(self,commit=True):
        user = super(NewUserForm, self).save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user

class UserLoginForm(AuthenticationForm):
    def __init__(self,*args, **kwargs):
        super(UserLoginForm, self).__init__(*args, **kwargs)
    
    username = UsernameField(widget=forms.TextInput(attrs={'class': 'user input_field', 'id': 'user', 'required': 'required'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'password input_field'}))


class UserRegisterForm(forms.ModelForm):
    user_name = forms.CharField(
        label='Enter Username', min_length=4, max_length=50, help_text='Required')
    email = forms.EmailField(max_length=100, help_text='Required', error_messages={
        'required': 'Sorry, you will need an email'})
    password = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(
        label='Repeat password', widget=forms.PasswordInput)


    class Meta:
        model = User
        fields = ('username', 'email',)

        
    def clean_user_name(self):
        user_name = self.cleaned_data['user_name'].lower()
        r = UserBase.objects.filter(user_name=user_name)
        if r.count():
            raise forms.ValidationError("Username already exists")
        return user_name

    def clean_password2(self):
        cd = self.cleaned_data
        if cd['password'] != cd['password2']:
            raise forms.ValidationError('Passwords not match.')
        return cd['password2']

    def clean_email(self):
        email = self.cleaned_data['email']
        if UserBase.objects.filter(email=email).exists():
            raise forms.ValidationError(
                'Please use another Email, that is already taken')
        return email

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update(
            {'class': 'input_field mb-3', 'placeholder': 'Username'})
        self.fields['email'].widget.attrs.update(
            {'class': 'input_field mb-3', 'placeholder': 'E-mail', 'name': 'email', 'id': 'id_email'})
        self.fields['password'].widget.attrs.update(
            {'class': 'input_field mb-3', 'placeholder': 'Password'})
        self.fields['password2'].widget.attrs.update(
            {'class': 'input_field', 'placeholder': 'Repeat Password'})   