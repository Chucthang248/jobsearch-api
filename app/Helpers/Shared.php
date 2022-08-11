<?php

namespace App\Helpers;

use Laravel\Passport\Client;

trait Shared{

    /**
     * format message response
     *
     * @param  $user_id, $name
     * @return associative array
    */ 
    public function MessageRespose($data){
        $resp = [
            'data' =>[
                'error' => !empty($data['error']) ? $data['error'] : [],
                'success' => !empty($data['success']) ? $data['success'] : '',
            ],
        ];

        foreach($data as $key => $value){
            if($key != 'error' && $key != 'success'){
                $resp['data'][$key] = $value;
            }
        }

        return $resp;
    }

}