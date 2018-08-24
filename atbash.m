function out=atbash(text)
% ATBASH Cipher encoder/decoder
% The Atbash cipher is a particular type of monoalphabetic cipher formed by
% taking the alphabet and mapping it to its reverse, so that the first
% letter becomes the last letter, the second letter becomes the second to
% last letter, and so on. For example, the English alphabet would work like
% this:      
%
% ABCDEFGHIJKLMNOPQRSTUVWXYZ
% ZYXWVUTSRQPONMLKJIHGFEDCBA
%
% Due to the fact that there is only one way to perform this, the Atbash
% cipher provides no communications security, as it lacks any sort of key. 
% The Atbash cipher can be seen as a special case of the affine cipher
% setting the keys = [25 25].
%
% Syntax: 	out=atbash(text)
%
%     Input:
%           text - It is a characters array to encode or decode
%     Output:
%           out - It is a structure
%           out.input = the input text
%           out.output = output text
%
% Examples:
%
% out=atbash('Holy horn')
%
% out = 
% 
%   struct with fields:
% 
%      input: 'Holy horn'
%     output: 'SLOBSLIM'
%
% out=atbash('Slobslim')
%
% out = 
% 
%   struct with fields:
% 
%      input: 'Slobslim'
%     output: 'HOLYHORN'
%
% See also rot, rot13, affine
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

tmp=affine(text,[25 25],1);
out.input=text;
out.output=tmp.encrypted;