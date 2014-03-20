# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'AccessAttempt'
        db.create_table(u'axes_accessattempt', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('user_agent', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('ip_address', self.gf('django.db.models.fields.IPAddressField')(max_length=15, null=True)),
            ('username', self.gf('django.db.models.fields.CharField')(max_length=255, null=True)),
            ('trusted', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('http_accept', self.gf('django.db.models.fields.CharField')(max_length=1025)),
            ('path_info', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('attempt_time', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('get_data', self.gf('django.db.models.fields.TextField')()),
            ('post_data', self.gf('django.db.models.fields.TextField')()),
            ('failures_since_start', self.gf('django.db.models.fields.PositiveIntegerField')()),
        ))
        db.send_create_signal(u'axes', ['AccessAttempt'])

        # Adding model 'AccessLog'
        db.create_table(u'axes_accesslog', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('user_agent', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('ip_address', self.gf('django.db.models.fields.IPAddressField')(max_length=15, null=True)),
            ('username', self.gf('django.db.models.fields.CharField')(max_length=255, null=True)),
            ('trusted', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('http_accept', self.gf('django.db.models.fields.CharField')(max_length=1025)),
            ('path_info', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('attempt_time', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('logout_time', self.gf('django.db.models.fields.DateTimeField')(null=True, blank=True)),
        ))
        db.send_create_signal(u'axes', ['AccessLog'])


    def backwards(self, orm):
        # Deleting model 'AccessAttempt'
        db.delete_table(u'axes_accessattempt')

        # Deleting model 'AccessLog'
        db.delete_table(u'axes_accesslog')


    models = {
        u'axes.accessattempt': {
            'Meta': {'ordering': "['-attempt_time']", 'object_name': 'AccessAttempt'},
            'attempt_time': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'failures_since_start': ('django.db.models.fields.PositiveIntegerField', [], {}),
            'get_data': ('django.db.models.fields.TextField', [], {}),
            'http_accept': ('django.db.models.fields.CharField', [], {'max_length': '1025'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'ip_address': ('django.db.models.fields.IPAddressField', [], {'max_length': '15', 'null': 'True'}),
            'path_info': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'post_data': ('django.db.models.fields.TextField', [], {}),
            'trusted': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'user_agent': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'username': ('django.db.models.fields.CharField', [], {'max_length': '255', 'null': 'True'})
        },
        u'axes.accesslog': {
            'Meta': {'ordering': "['-attempt_time']", 'object_name': 'AccessLog'},
            'attempt_time': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'http_accept': ('django.db.models.fields.CharField', [], {'max_length': '1025'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'ip_address': ('django.db.models.fields.IPAddressField', [], {'max_length': '15', 'null': 'True'}),
            'logout_time': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'path_info': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'trusted': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'user_agent': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'username': ('django.db.models.fields.CharField', [], {'max_length': '255', 'null': 'True'})
        }
    }

    complete_apps = ['axes']